"""
tenable_dashboard.py
====================
Dashboard Tenable.io — Scans del día de hoy.
Output optimizado para Power BI: datos planos.

Ejecutar:  python tenable_dashboard.py
Genera:    tenable_scans_YYYYMMDD_HHMM.csv
           tenable_hosts_YYYYMMDD_HHMM.csv
"""

import os
import time
import requests
import pandas as pd
from datetime import datetime, date
from typing import Optional, List, Dict
from dotenv import load_dotenv

load_dotenv(os.getenv("ENV_PATH"))

BASE_URL        = "https://cloud.tenable.com"
TODAY           = date.today()
ACTIVE_STATUSES = {"running", "pending", "resuming", "stopping", "initializing"}


# ─────────────────────────────────────────────
# API Client
# ─────────────────────────────────────────────
class TenableAPI:
    def __init__(self):
        ak = os.getenv("IO_ACCESS_KEY") or os.getenv("TENABLE_ACCESS_KEY")
        sk = os.getenv("IO_SECRET_KEY")  or os.getenv("TENABLE_SECRET_KEY")

        if not ak or not sk:
            raise EnvironmentError(
                "Credenciales no encontradas. "
                "Define IO_ACCESS_KEY y IO_SECRET_KEY en tu archivo .env"
            )

        self.session = requests.Session()
        self.session.headers.update({
            "accept":       "application/json",
            "content-type": "application/json",
            "X-ApiKeys":    f"accessKey={ak};secretKey={sk}",
        })

    def _get(self, endpoint: str, params: dict = None, retries: int = 3) -> Optional[dict]:
        url = f"{BASE_URL}{endpoint}"

        for attempt in range(1, retries + 1):
            try:
                r = self.session.get(url, params=params, timeout=30)

                if r.status_code == 429:
                    wait = int(r.headers.get("Retry-After", 15))
                    print(f"  Rate limit — esperando {wait}s...")
                    time.sleep(wait)
                    continue

                r.raise_for_status()
                return r.json()

            except requests.RequestException as e:
                print(f"  Intento {attempt}/{retries} fallido: {e}")
                if attempt < retries:
                    time.sleep(5 * attempt)

        return None

    def list_scans(self) -> List[dict]:
        data = self._get("/scans")
        return (data or {}).get("scans", [])

    def get_scan_details(self, scan_id: int) -> Optional[dict]:
        return self._get(f"/scans/{scan_id}")


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def epoch_to_dt(epoch) -> str:
    if not epoch:
        return ""
    try:
        return datetime.fromtimestamp(int(epoch)).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return ""

def is_today(epoch) -> bool:
    if not epoch:
        return False
    try:
        return datetime.fromtimestamp(int(epoch)).date() == TODAY
    except Exception:
        return False


def filter_scans_today(scans: List[dict]) -> List[dict]:
    """Retorna scans con actividad hoy o actualmente activos."""
    result = []

    for s in scans:
        status = (s.get("status") or "").lower()

        timestamps = [
            s.get("starttime"),
            s.get("last_modification_date"),
            s.get("creation_date"),
        ]

        if any(is_today(t) for t in timestamps) or status in ACTIVE_STATUSES:
            result.append(s)

    return result


# ─────────────────────────────────────────────
# Data Builders
# ─────────────────────────────────────────────
def build_dataframes(scan_details: Dict[int, dict]):

    detalle_rows = []
    host_rows    = []

    for scan_id, details in scan_details.items():

        if not details:
            continue

        info = details.get("info") or {}
        start = info.get("scan_start")
        end   = info.get("scan_end")

        # ───── Detalle Scan ─────
        detalle_rows.append({
            "Scan_ID":        scan_id,
            "Nombre":         info.get("name", ""),
            "Estado":         info.get("status", ""),
            "Hosts_Totales":  info.get("hostcount", 0),
            "Inicio":         epoch_to_dt(start),
            "Fin":            epoch_to_dt(end),
        })

        # ───── Hosts ─────
        scan_name = info.get("name", f"Scan {scan_id}")

        for h in (details.get("hosts") or []):
            host_rows.append({
                "Scan_ID":     scan_id,
                "Scan_Nombre": scan_name,
                "Hostname_IP": h.get("hostname", ""),
            })

    detalle_df = pd.DataFrame(detalle_rows)
    hosts_df   = pd.DataFrame(host_rows)

    return detalle_df, hosts_df


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
def main():

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    date_tag  = datetime.now().strftime("%Y%m%d_%H%M")

    output_scans = f"tenable_scans_{date_tag}.csv"
    output_hosts = f"tenable_hosts_{date_tag}.csv"

    print("=" * 55)
    print("  TENABLE DASHBOARD")
    print(f"  {timestamp}")
    print(f"  Filtro: {TODAY.strftime('%d/%m/%Y')}")
    print("=" * 55)

    api = TenableAPI()

    # 1️⃣ Lista scans
    print("\n[1/4] Obteniendo lista de scans...")
    all_scans = api.list_scans()

    if not all_scans:
        print("  Error: no se obtuvo lista. Verifica credenciales.")
        return

    print(f"  {len(all_scans)} scans encontrados")

    # 2️⃣ Filtro hoy
    print("\n[2/4] Filtrando scans de hoy...")
    scans_hoy = filter_scans_today(all_scans)
    scan_ids  = [s["id"] for s in scans_hoy]

    print(f"  {len(scan_ids)} scans relevantes")

    # 3️⃣ Obtener detalles (UNA sola llamada por scan)
    print("\n[3/4] Obteniendo detalles...")
    scan_details = {}

    for scan_id in scan_ids:
        print(f"    Scan ID {scan_id}...")
        scan_details[scan_id] = api.get_scan_details(scan_id)

    detalle_df, hosts_df = build_dataframes(scan_details)

    print(f"  {len(hosts_df)} hosts procesados")

    # 4️⃣ Exportar
    print("\n[4/4] Exportando CSV...")

    detalle_df.to_csv(output_scans, index=False, encoding="utf-8")
    hosts_df.to_csv(output_hosts, index=False, encoding="utf-8")

    print("\n" + "=" * 55)
    print(f"  Scans CSV  : {output_scans}")
    print(f"  Hosts CSV  : {output_hosts}")
    print(f"  Detalle    : {len(detalle_df)} filas")
    print(f"  Hosts      : {len(hosts_df)} filas")
    print("=" * 55)


if __name__ == "__main__":
    main()
