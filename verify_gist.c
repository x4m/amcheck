/*-------------------------------------------------------------------------
 *
 * verify_gist.c
 *		Verifies the integrity of GiST indexes based on invariants.
 *
 * Verification checks that all paths in GiST graph are contatining
 * consisnent keys: tuples on parent pages consistently include tuples
 * from children pages. Also, verification checks graph invariants:
 * internal page must have at least one downlinks, internal page can
 * reference either only leaf pages or only internal pages.
 *
 *
 * Portions Copyright (c) 2018, Andrey Borodin
 * Portions Copyright (c) 2016-2018, Peter Geoghegan
 * Portions Copyright (c) 1996-2018, The PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, The Regents of the University of California
 *
 * IDENTIFICATION
 *	  amcheck_next/verify_gist.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/gist_private.h"
#include "access/htup_details.h"
#include "access/transam.h"
#include "bloomfilter.h"
#include "catalog/index.h"
#include "catalog/pg_am.h"
#include "commands/tablecmds.h"
#include "miscadmin.h"
#include "storage/lmgr.h"
#include "utils/memutils.h"
#include "utils/snapmgr.h"

typedef struct GistScanItem
{
	GistNSN		parentlsn;
	BlockNumber blkno;
	struct GistScanItem *next;
} GistScanItem;

typedef struct GistCheckState
{
	/*
	 * Unchanging state, established at start of verification:
	 */

	/* B-Tree Index Relation and associated heap relation */
	Relation	rel;
	Relation	heaprel;
	/* ShareLock held on heap/index, rather than AccessShareLock? */
	bool		readonly;
	/* Also verifying heap has no unindexed tuples? */
	bool		heapallindexed;
	/* Per-page context */
	MemoryContext targetcontext;
	/* Buffer access strategy */
	BufferAccessStrategy checkstrategy;

	/*
	 * Mutable state, for verification of particular page:
	 */

	/* Current target page */
	Page		target;
	/* Target block number */
	BlockNumber targetblock;
	/* Target page's LSN */
	XLogRecPtr	targetlsn;

	/*
	 * Mutable state, for optional heapallindexed verification:
	 */

	/* Bloom filter fingerprints B-Tree index */
	bloom_filter *filter;
	/* Debug counter */
	int64		heaptuplespresent;
} GistCheckState;

/*
 * For every tuple on page check if it is contained by tuple on parent page
 */
static inline void
gist_check_page_keys(Relation rel, Page parentpage, Page page, IndexTuple parent, GISTSTATE *state, bloom_filter *filter)
{
	OffsetNumber i,
				maxoff = PageGetMaxOffsetNumber(page);

	for (i = FirstOffsetNumber; i <= maxoff; i = OffsetNumberNext(i))
	{
		ItemId iid = PageGetItemId(page, i);
		IndexTuple idxtuple = (IndexTuple) PageGetItem(page, iid);

		if (GistTupleIsInvalid(idxtuple))
			ereport(LOG,
					(errmsg("index \"%s\" contains an inner tuple marked as invalid",
							RelationGetRelationName(rel)),
					 errdetail("This is caused by an incomplete page split at crash recovery before upgrading to PostgreSQL 9.1."),
					 errhint("Please REINDEX it.")));

		/*
		 * Tree is inconsistent if adjustement is necessary for any parent tuple
		 */
		if (gistgetadjusted(rel, parent, idxtuple, state))
			ereport(ERROR,
					(errcode(ERRCODE_INDEX_CORRUPTED),
					 errmsg("index \"%s\" has inconsistent records",
							RelationGetRelationName(rel))));
		if (filter && GistPageIsLeaf(page) && !ItemIdIsDead(iid))
		{
		elog(NOTICE,"AM: addelement");
			bloom_add_element(filter, (unsigned char *) idxtuple,
							  IndexTupleSize(idxtuple));
		}
	}
}

/* Check of an internal page. Hold locks on two pages at a time (parent+child). */
static inline bool
gist_check_internal_page(Relation rel, Page page, BufferAccessStrategy strategy, GISTSTATE *state, bloom_filter *filter)
{
	bool has_leafs = false;
	bool has_internals = false;
	OffsetNumber i,
				maxoff = PageGetMaxOffsetNumber(page);

	for (i = FirstOffsetNumber; i <= maxoff; i = OffsetNumberNext(i))
	{
		ItemId iid = PageGetItemId(page, i);
		IndexTuple idxtuple = (IndexTuple) PageGetItem(page, iid);

		BlockNumber child_blkno = ItemPointerGetBlockNumber(&(idxtuple->t_tid));	
		Buffer		buffer;
		Page child_page;

		if (GistTupleIsInvalid(idxtuple))
			ereport(LOG,
					(errmsg("index \"%s\" contains an inner tuple marked as invalid",
							RelationGetRelationName(rel)),
					 errdetail("This is caused by an incomplete page split at crash recovery before upgrading to PostgreSQL 9.1."),
					 errhint("Please REINDEX it.")));
		
		buffer = ReadBufferExtended(rel, MAIN_FORKNUM, child_blkno,
									RBM_NORMAL, strategy);

		LockBuffer(buffer, GIST_SHARE);
		gistcheckpage(rel, buffer);
		child_page = (Page) BufferGetPage(buffer);

		has_leafs = has_leafs || GistPageIsLeaf(child_page);
		has_internals = has_internals || !GistPageIsLeaf(child_page);
		gist_check_page_keys(rel, page, child_page, idxtuple, state, filter);

		UnlockReleaseBuffer(buffer);
	}

	if (!(has_leafs || has_internals))
		ereport(ERROR,
				(errcode(ERRCODE_INDEX_CORRUPTED),
				 errmsg("index \"%s\" internal page has no downlink references",
						RelationGetRelationName(rel))));


	if (has_leafs == has_internals)
		ereport(ERROR,
				(errcode(ERRCODE_INDEX_CORRUPTED),
				 errmsg("index \"%s\" page references both internal and leaf pages",
						RelationGetRelationName(rel))));
	
	return has_internals;
}

/* add pages with unfinished split to scan */
static void
pushStackIfSplited(Page page, GistScanItem *stack)
{
	GISTPageOpaque opaque = GistPageGetOpaque(page);

	if (stack->blkno != GIST_ROOT_BLKNO && !XLogRecPtrIsInvalid(stack->parentlsn) &&
		(GistFollowRight(page) || stack->parentlsn < GistPageGetNSN(page)) &&
		opaque->rightlink != InvalidBlockNumber /* sanity check */ )
	{
		/* split page detected, install right link to the stack */

		GistScanItem *ptr = (GistScanItem *) palloc(sizeof(GistScanItem));

		ptr->blkno = opaque->rightlink;
		ptr->parentlsn = stack->parentlsn;
		ptr->next = stack->next;
		stack->next = ptr;
	}
}

static void
gist_tuple_present_callback(Relation index, HeapTuple htup, Datum *values,
						  bool *isnull, bool tupleIsAlive, void *checkstate)
{
	GistCheckState *state = (GistCheckState *) checkstate;
	IndexTuple		 itup;

	Assert(state->heapallindexed);

	/* Must recheck visibility when only AccessShareLock held */
	if (!state->readonly)
	{
		TransactionId	xmin;

		/*
		 * Don't test for presence in index where xmin not at least old enough
		 * that we know for sure that absence of index tuple wasn't just due to
		 * some transaction performing insertion after our verifying index
		 * traversal began.  (Actually, the cut-off used is a point where
		 * preceding write transactions must have committed/aborted.  We should
		 * have already fingerprinted all index tuples for all such preceding
		 * transactions, because the cut-off was established before our index
		 * traversal even began.)
		 *
		 * You might think that the fact that an MVCC snapshot is used by the
		 * heap scan (due to our indicating that this is the first scan of a
		 * CREATE INDEX CONCURRENTLY index build) would make this test
		 * redundant.  That's not quite true, because with current
		 * IndexBuildHeapScan() interface caller cannot do the MVCC snapshot
		 * acquisition itself.  Heap tuple coverage is thereby similar to the
		 * coverage we could get by using earliest transaction snapshot
		 * directly.  It's easier to do this than to adopt the
		 * IndexBuildHeapScan() interface to our narrow requirements.
		 */
		Assert(tupleIsAlive);
		xmin = HeapTupleHeaderGetXmin(htup->t_data);
		if (!TransactionIdPrecedes(xmin, TransactionXmin))
			return;
	}

	/*
	 * Generate an index tuple.
	 *
	 * Note that we rely on deterministic index_form_tuple() TOAST compression.
	 * If index_form_tuple() was ever enhanced to compress datums out-of-line,
	 * or otherwise varied when or how compression was applied, our assumption
	 * would break, leading to false positive reports of corruption.  For now,
	 * we don't decompress/normalize toasted values as part of fingerprinting.
	 */
	itup = index_form_tuple(RelationGetDescr(index), values, isnull);
	itup->t_tid = htup->t_self;

	/* Probe Bloom filter -- tuple should be present */
	if (bloom_lacks_element(state->filter, (unsigned char *) itup,
							IndexTupleSize(itup)))
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg("heap tuple (%u,%u) from table \"%s\" lacks matching index tuple within index \"%s\"",
						ItemPointerGetBlockNumber(&(itup->t_tid)),
						ItemPointerGetOffsetNumber(&(itup->t_tid)),
						RelationGetRelationName(state->heaprel),
						RelationGetRelationName(state->rel)),
				 !state->readonly
				 ? errhint("Retrying verification using the function bt_index_parent_check() might provide a more specific error.")
				 : 0));

	state->heaptuplespresent++;
	pfree(itup);
}

/* 
 * Main entry point for GiST check. Allocates memory context and scans 
 * through GiST graph.
 */
static inline void
gist_check_keys_consistency(Relation rel, bool heapallindexed)
{
	GistScanItem *stack,
			   *ptr;
	Relation	heaprel;
	bloom_filter *filter = NULL;
	
	BufferAccessStrategy strategy = GetAccessStrategy(BAS_BULKREAD);

    MemoryContext mctx = AllocSetContextCreate(CurrentMemoryContext,
												 "amcheck context",
#if PG_VERSION_NUM >= 110000
												 ALLOCSET_DEFAULT_SIZES);
#else
												 ALLOCSET_DEFAULT_MINSIZE,
												 ALLOCSET_DEFAULT_INITSIZE,
												 ALLOCSET_DEFAULT_MAXSIZE);
#endif

	MemoryContext oldcontext = MemoryContextSwitchTo(mctx);
	GISTSTATE *state = initGISTstate(rel);

	if (heapallindexed)
	{
		int64	total_elems;
		uint32	seed;

		/* Size Bloom filter based on estimated number of tuples in index */
		total_elems = (int64) rel->rd_rel->reltuples;
		/* Random seed relies on backend srandom() call to avoid repetition */
		seed = random();
		/* Create Bloom filter to fingerprint index */
		filter = bloom_create(total_elems, maintenance_work_mem, seed);
		
		heaprel = heap_open(IndexGetRelation(rel->rd_id, true), AccessShareLock);
	}

	stack = (GistScanItem *) palloc0(sizeof(GistScanItem));
	stack->blkno = GIST_ROOT_BLKNO;

	while (stack)
	{
		Buffer		buffer;
		Page		page;
		OffsetNumber i,
					maxoff;
		IndexTuple	idxtuple;
		ItemId		iid;

		buffer = ReadBufferExtended(rel, MAIN_FORKNUM, stack->blkno,
									RBM_NORMAL, strategy);
		LockBuffer(buffer, GIST_SHARE);
		gistcheckpage(rel, buffer);
		page = (Page) BufferGetPage(buffer);

		if (GistPageIsLeaf(page))
		{
			/* should never happen unless it is root */
			Assert(stack->blkno == GIST_ROOT_BLKNO);
		}
		else
		{
			/* check for split proceeded after look at parent */
			pushStackIfSplited(page, stack);

			maxoff = PageGetMaxOffsetNumber(page);

			if (gist_check_internal_page(rel, page, strategy, state, filter))
			{
				for (i = FirstOffsetNumber; i <= maxoff; i = OffsetNumberNext(i))
				{
					iid = PageGetItemId(page, i);
					idxtuple = (IndexTuple) PageGetItem(page, iid);

					ptr = (GistScanItem *) palloc(sizeof(GistScanItem));
					ptr->blkno = ItemPointerGetBlockNumber(&(idxtuple->t_tid));
					ptr->parentlsn = BufferGetLSNAtomic(buffer);
					ptr->next = stack->next;
					stack->next = ptr;
				}
			}
		}

		UnlockReleaseBuffer(buffer);

		ptr = stack->next;
		pfree(stack);
		stack = ptr;
	}

	if (heapallindexed)
	{
		IndexInfo  *indexinfo;
		GistCheckState state;
		state.filter = filter;
		state.heapallindexed = true;
		state.rel = rel;
		state.heaprel = heaprel;

		indexinfo = BuildIndexInfo(rel);

		indexinfo->ii_Concurrent = true;
		
		indexinfo->ii_Unique = false;
		indexinfo->ii_ExclusionOps = NULL;
		indexinfo->ii_ExclusionProcs = NULL;
		indexinfo->ii_ExclusionStrats = NULL;

		IndexBuildHeapScan(heaprel, rel, indexinfo, true,
						   gist_tuple_present_callback, (void *) &state);

		ereport(DEBUG1,
				(errmsg_internal("finished verifying presence of " INT64_FORMAT " tuples (proportion of bits set: %f) from table \"%s\"",
								 state.heaptuplespresent, bloom_prop_bits_set(state.filter),
								 RelationGetRelationName(heaprel))));

		bloom_free(filter);

		if (heaprel)
			heap_close(heaprel, AccessShareLock);
	}

    MemoryContextSwitchTo(oldcontext);
    MemoryContextDelete(mctx);
}

/* Check that relation is eligible for GiST verification */
static inline void
gist_index_checkable(Relation rel)
{
	if (rel->rd_rel->relkind != RELKIND_INDEX ||
		rel->rd_rel->relam != GIST_AM_OID)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("only GiST indexes are supported as targets for this verification"),
				 errdetail("Relation \"%s\" is not a GiST index.",
						   RelationGetRelationName(rel))));

	if (RELATION_IS_OTHER_TEMP(rel))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("cannot access temporary tables of other sessions"),
				 errdetail("Index \"%s\" is associated with temporary relation.",
						   RelationGetRelationName(rel))));

	if (!IndexIsValid(rel->rd_index))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("cannot check index \"%s\"",
						RelationGetRelationName(rel)),
				 errdetail("Index is not valid")));
}

PG_FUNCTION_INFO_V1(gist_index_check_next);

Datum
gist_index_check_next(PG_FUNCTION_ARGS)
{
	Oid			indrelid = PG_GETARG_OID(0);
	Relation	indrel;
	bool		heapallindexed = false;

	if (PG_NARGS() == 2)
		heapallindexed = PG_GETARG_BOOL(1);

	indrel = index_open(indrelid, ShareLock);

	gist_index_checkable(indrel);
	gist_check_keys_consistency(indrel, heapallindexed);		

	index_close(indrel, ShareLock);

	PG_RETURN_VOID();
}
