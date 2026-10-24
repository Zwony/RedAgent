"""Vector Knowledge Store for red teaming attack vectors and benchmark patterns."""
import os
import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from config.settings import settings
from redagent.core.logger import get_logger
from redagent.knowledge.seed_data import DEFAULT_SEEDS
from redagent.schemas.test_case import AttackTechnique, OWASPCategory

logger = get_logger(__name__)

try:
    import chromadb
    from chromadb.config import Settings as ChromaSettings
    HAS_CHROMADB = True
except ImportError:
    HAS_CHROMADB = False


class VectorDocument(BaseModel):
    """Document stored in the security vector store."""
    id: str
    content: str
    category: OWASPCategory
    technique: AttackTechnique
    metadata: Dict[str, Any] = Field(default_factory=dict)
    score: float = 0.0


class SecurityVectorStore:
    """Vector database client managing attack templates, test seeds, and OWASP rubrics.
    
    Seamlessly integrates with ChromaDB when installed, and provides a lightweight
    in-memory lexical/semantic vector store fallback if ChromaDB is not installed.
    """

    def __init__(self, collection_name: str = "redagent_vectors", persist_dir: Optional[str] = None):
        self.collection_name = collection_name
        self.persist_dir = persist_dir or settings.CHROMADB_PATH
        self._memory_docs: List[VectorDocument] = []
        self._chroma_collection = None

        if HAS_CHROMADB:
            try:
                os.makedirs(self.persist_dir, exist_ok=True)
                client = chromadb.PersistentClient(path=self.persist_dir)
                self._chroma_collection = client.get_or_create_collection(
                    name=self.collection_name,
                    metadata={"hnsw:space": "cosine"},
                )
                logger.info("ChromaDB vector store initialized", path=self.persist_dir)
            except Exception as exc:
                logger.warning("ChromaDB initialization failed, using memory store", error=str(exc))
                self._chroma_collection = None
        else:
            logger.info("ChromaDB not installed; using in-memory semantic vector store.")

        # Seed with initial benchmark vectors
        self.seed_defaults()

    def seed_defaults(self) -> None:
        """Populate vector store with default OWASP LLM seeds if empty."""
        docs = [
            VectorDocument(
                id=s["id"],
                content=s["content"],
                category=s["category"],
                technique=s["technique"],
                metadata=s["metadata"],
            )
            for s in DEFAULT_SEEDS
        ]
        self.add_documents(docs)

    def add_documents(self, docs: List[VectorDocument]) -> None:
        """Add documents to persistent vector database or memory index."""
        existing_ids = {d.id for d in self._memory_docs}
        for doc in docs:
            if doc.id not in existing_ids:
                self._memory_docs.append(doc)

        if self._chroma_collection is not None:
            try:
                ids = [d.id for d in docs]
                documents = [d.content for d in docs]
                metadatas = [
                    {
                        "category": d.category.value,
                        "technique": d.technique.value,
                        **{k: str(v) for k, v in d.metadata.items()},
                    }
                    for d in docs
                ]
                self._chroma_collection.upsert(
                    ids=ids,
                    documents=documents,
                    metadatas=metadatas,
                )
            except Exception as exc:
                logger.error("Failed to upsert to ChromaDB", error=str(exc))

    def _tokenize(self, text: str) -> set[str]:
        """Simple word tokenization for lexical search fallback."""
        return set(re.findall(r"\w+", text.lower()))

    def search(
        self,
        query: str,
        top_k: int = 3,
        category: Optional[OWASPCategory] = None,
    ) -> List[VectorDocument]:
        """Query vector database for similar attack patterns or test seeds."""
        if self._chroma_collection is not None:
            try:
                where_filter = {"category": category.value} if category else None
                results = self._chroma_collection.query(
                    query_texts=[query],
                    n_results=top_k,
                    where=where_filter,
                )
                matched: List[VectorDocument] = []
                if results and "documents" in results and results["documents"]:
                    docs = results["documents"][0]
                    ids = results["ids"][0]
                    metas = results["metadatas"][0] if "metadatas" in results else [{}] * len(docs)
                    distances = results["distances"][0] if "distances" in results and results["distances"] else [0.0] * len(docs)

                    for doc_id, content, meta, dist in zip(ids, docs, metas, distances):
                        matched.append(
                            VectorDocument(
                                id=doc_id,
                                content=content,
                                category=OWASPCategory(meta.get("category", OWASPCategory.LLM01_PROMPT_INJECTION.value)),
                                technique=AttackTechnique(meta.get("technique", AttackTechnique.DIRECT_PROMPT_INJECTION.value)),
                                metadata=meta,
                                score=1.0 - float(dist) if dist else 1.0,
                            )
                        )
                    if matched:
                        return matched
            except Exception as exc:
                logger.warning("ChromaDB query failed; falling back to memory search", error=str(exc))

        # Memory search fallback using Jaccard / token overlap similarity
        query_tokens = self._tokenize(query)
        candidates = self._memory_docs
        if category:
            candidates = [d for d in candidates if d.category == category]

        scored: List[VectorDocument] = []
        for doc in candidates:
            doc_tokens = self._tokenize(doc.content)
            intersection = query_tokens.intersection(doc_tokens)
            union = query_tokens.union(doc_tokens)
            score = len(intersection) / len(union) if union else 0.0
            doc_copy = doc.model_copy()
            doc_copy.score = score
            scored.append(doc_copy)

        scored.sort(key=lambda x: x.score, reverse=True)
        return scored[:top_k]
