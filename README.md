# 3GPP Log Analyzer — AI-Powered RCA

An intelligent log analysis tool for 3GPP protocol engineers.  
Detects failure points in telecom protocol logs, maps them to 3GPP specifications,  
and generates Root Cause Analysis reports using **Groq LLM + RAG + MCP tools**.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        Browser (Chat UI)                          │
│   ┌─────────────────────┐    ┌───────────────────────────────┐   │
│   │  Log Upload / Input  │    │  Interactive Chat Window       │   │
│   └──────────┬──────────┘    └───────────────┬───────────────┘   │
└──────────────┼───────────────────────────────┼───────────────────┘
               │ HTTP POST                      │ HTTP POST / SSE
               ▼                                ▼
┌──────────────────────────────────────────────────────────────────┐
│                     FastAPI Backend                                │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │  /api/analysis│  │  /api/chat   │  │   /api/admin           │  │
│  └──────┬───────┘  └──────┬───────┘  └────────────────────────┘  │
│         │                 │                                        │
│         ▼                 ▼                                        │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │              Analysis Pipeline                                │ │
│  │                                                               │ │
│  │  1. Log Parser ──────────────── Detects 30+ failure patterns │ │
│  │     (app/parsers/log_parser.py)  Maps to 3GPP spec sections   │ │
│  │                                                               │ │
│  │  2. MCP Tool Registry ────────── parse_logs                   │ │
│  │     (app/mcp/tool_registry.py)   get_failure_summary          │ │
│  │                                  detect_failure_chain         │ │
│  │                                  query_3gpp_spec              │ │
│  │                                  get_3gpp_timer_info          │ │
│  │                                  get_cause_code_explanation   │ │
│  │                                                               │ │
│  │  3. RAG Pipeline ─────────────── ChromaDB vector store        │ │
│  │     (app/rag/vector_store.py)    sentence-transformers embed   │ │
│  │                                  3GPP KB (6 spec documents)   │ │
│  │                                                               │ │
│  │  4. Groq LLM ─────────────────── llama3-70b-8192              │ │
│  │     (app/services/groq_llm.py)   RCA generation               │ │
│  │                                  Streaming chat               │ │
│  └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────────┐
│              3GPP Knowledge Base (knowledge_base/)                │
│  3gpp_rrc.md · 3gpp_nas.md · 3gpp_ngap_s1ap.md                  │
│  3gpp_mac_rlc_pdcp.md · 3gpp_handover.md · 3gpp_qos_bearer.md   │
│  3gpp_error_codes.md                                             │
└──────────────────────────────────────────────────────────────────┘
```

## Detected Failure Types

| Layer | Failures Detected | 3GPP Spec |
|-------|------------------|-----------|
| RRC   | Setup, Reject, Re-establishment, RLF, T300/T301/T304/T310 expiry, HO failure | TS 38.331 |
| NAS   | Registration Reject, Auth Failure, Security Mode Reject, PDU Session Failure | TS 24.501 |
| MAC   | RACH Failure, HARQ Max Retx, Scheduling Failure | TS 38.321 |
| RLC   | maxRetxThreshold, Reordering Timeout, SDU Discard | TS 38.322 |
| PDCP  | Integrity Failure, Ciphering Error, Discard Timer | TS 38.323 |
| NGAP  | HO Preparation Failure, Initial Context Failure, PDU Session Failure | TS 38.413 |
| S1AP  | Setup Failure, HO Failure, E-RAB Failure | TS 36.413 |
| GTP   | Context Not Found, Interface Down | TS 29.281 |

## Quick Start

### 1. Prerequisites
- Python 3.10+
- Groq API key (free at https://console.groq.com)

### 2. Run Setup Script (Windows)
```powershell
cd f:\AI_Training\Analysis_core
.\setup_and_run.ps1
```

### 3. Manual Setup
```bash
# Create and activate venv
python -m venv venv
venv\Scripts\activate      # Windows
# source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and set GROQ_API_KEY=your_key_here

# Run
python run.py
```

### 4. Open Browser
Navigate to **http://localhost:8000**

## Configuration (.env)

| Variable | Default | Description |
|----------|---------|-------------|
| `GROQ_API_KEY` | — | **Required** — Get at console.groq.com |
| `GROQ_MODEL` | `llama3-70b-8192` | Groq model to use |
| `CHROMA_DB_PATH` | `./chroma_db` | ChromaDB persistence path |
| `KNOWLEDGE_BASE_PATH` | `./knowledge_base` | Path to 3GPP spec documents |
| `EMBED_MODEL` | `all-MiniLM-L6-v2` | Sentence-transformer model |

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/analysis/text` | Analyze raw log text (JSON) |
| POST | `/api/analysis/upload` | Upload log file (multipart) |
| POST | `/api/analysis/quick` | Parse only — no LLM |
| POST | `/api/chat/message` | Chat message |
| POST | `/api/chat/stream` | Streaming chat (SSE) |
| GET  | `/api/chat/mcp-tools` | List MCP tools |
| POST | `/api/chat/mcp-call` | Call an MCP tool directly |
| GET  | `/api/admin/status` | System status |
| POST | `/api/admin/rebuild-index` | Re-ingest knowledge base |
| GET  | `/docs` | Swagger UI |

## Project Structure

```
Analysis_core/
├── app/
│   ├── main.py                 # FastAPI app + lifespan
│   ├── parsers/
│   │   └── log_parser.py       # 3GPP log parser (30+ failure patterns)
│   ├── rag/
│   │   └── vector_store.py     # ChromaDB + sentence-transformers RAG
│   ├── mcp/
│   │   └── tool_registry.py    # MCP tool registry (6 tools)
│   ├── services/
│   │   ├── groq_llm.py         # Groq LLM client (sync + async + streaming)
│   │   └── analysis_pipeline.py # Orchestration pipeline
│   └── routers/
│       ├── analysis.py         # Analysis endpoints
│       ├── chat.py             # Chat + MCP endpoints
│       └── admin.py            # Admin endpoints
├── knowledge_base/             # 3GPP spec documents (RAG source)
├── templates/
│   └── index.html              # Chat UI + Analysis UI
├── static/
│   ├── css/style.css           # Dark theme UI
│   └── js/app.js               # Frontend logic
├── chroma_db/                  # ChromaDB vector store (auto-created)
├── sample_logs/                # Example log files
├── requirements.txt
├── .env.example
└── run.py                      # Entry point
```
