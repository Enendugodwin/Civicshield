# Architecture

CivicShield: React+TS+Vite+Tailwind frontend (`civicshield/frontend`), FastAPI+Pydantic+SQLAlchemy backend (`civicshield/backend`), SQLite local (PostgreSQL-compatible models), deterministic rule engine (`engine/`), risk scorer (`services/risk.py`), AI provider adapter (`ai/`), recovery simulator (`recovery/`).

Data flow: Seed water-utility assets/relationships → BaselineGuard rules → Findings → ImpactEngine scores → FixPilot plans (Muse Spark w/ fallback) → simulated verify → RecoveryLab scenarios → Reports. All findings reference rule version + evidence. AI never writes infra directly; approvals + audit log gate actions.
