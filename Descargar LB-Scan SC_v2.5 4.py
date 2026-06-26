"""
tenable_dashboard.py
====================
Dashboard Tenable.io — Scans del dia de hoy.
Output optimizado para Power BI: datos planos, columnas homogeneas.

Ejecutar:  python tenable_dashboard.py
Genera:    tenable_scans_YYYYMMDD_HHMM.csv
           tenable_hosts_YYYYMMDD_HHMM.csv
  csv 1 — Detalle_Scan
  csv 2 — Hosts
"""

import os
import time
import requests
import pandas as pd
from datetime import datetime, date
from typing import Optional, List
from dotenv import load_dotenv
from datetime import datetime, timedelta

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
        self.headers = {
            "accept":       "application/json",
            "content-type": "application/json",
            "X-ApiKeys":    f"accessKey={ak};secretKey={sk}",
        }

    def _get(self, endpoint: str, params: dict = None, retries: int = 3) -> Optional[dict]:
        url = f"{BASE_URL}{endpoint}"
        for attempt in range(1, retries + 1):
            try:
                r = requests.get(url, headers=self.headers, params=params, timeout=30)
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
        return (data or {}).get("scans") or []

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

def duration_str(start, end) -> str:
    try:
        secs = int(end) - int(start)
        if secs < 0:
            return ""
        h, rem = divmod(secs, 3600)
        m, s   = divmod(rem, 60)
        return f"{h}h {m:02d}m {s:02d}s" if h else f"{m}m {s:02d}s"
    except Exception:
        return ""

def elapsed(start_epoch) -> str:
    if not start_epoch:
        return ""
    try:
        secs = int(datetime.now().timestamp()) - int(start_epoch)
        if secs < 0:
            return ""
        h, rem = divmod(secs, 3600)
        m, s   = divmod(rem, 60)
        return f"{h}h {m:02d}m {s:02d}s" if h else f"{m}m {s:02d}s"
    except Exception:
        return ""

def is_today(epoch) -> bool:
    if not epoch:
        return False
    try:
        return datetime.fromtimestamp(int(epoch)).date() == TODAY
    except Exception:
        return False


TODAY = datetime.now().date()
YESTERDAY = TODAY - timedelta(days=3)

def is_yesterday(epoch) -> bool:
    if not epoch:
        return False
    try:
        return datetime.fromtimestamp(int(epoch)).date() == YESTERDAY
    except Exception:
        return False

def filter_scans_today(scans: List[dict]) -> List[dict]:
    """Retorna solo scans con actividad hoy o activos en este momento."""
    result = []
    for s in scans:
        status = (s.get("status") or "").lower()
        timestamps = [s.get("starttime"), s.get("last_modification_date"), s.get("creation_date")]
        if any(is_yesterday(t) for t in timestamps) or status in ACTIVE_STATUSES:
            result.append(s)
    return result


# ─────────────────────────────────────────────
# DataFrames
# ─────────────────────────────────────────────
def build_detalle_scan(scan_ids: List[int], api: TenableAPI) -> pd.DataFrame:
    rows = []
    for scan_id in scan_ids:
        print(f"    Scan ID {scan_id}...")
        details = api.get_scan_details(scan_id)
        if not details:
            continue
        info  = details.get("info") or {}
        start = info.get("scan_start")
        end   = info.get("scan_end")

        rows.append({
            "Scan_ID":           scan_id,
            "Nombre":            info.get("name", ""),
            #"UUID":              info.get("scan_uuid", ""),
            "Estado":            info.get("status", ""),
            #"Tipo":              info.get("scan_type", ""),
            #"Politica":          info.get("policy", ""),
            #"Owner":             info.get("owner", ""),
            #"Owner_UUID":        info.get("owner_uuid", ""),
            "Hosts_Totales":     info.get("hostcount", 0),
            #"Hosts_Escaneados":  info.get("numhosts", 0),
            "Inicio":            epoch_to_dt(start),
            "Fin":               epoch_to_dt(end),
            #"Duracion":          duration_str(start, end) if end else elapsed(start),
            #"Fecha_Reporte":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })
    return pd.DataFrame(rows)


def build_hosts(scan_ids: List[int], api: TenableAPI) -> pd.DataFrame:
    rows = []
    for scan_id in scan_ids:
        details = api.get_scan_details(scan_id)
        if not details:
            continue
        scan_name = (details.get("info") or {}).get("name", f"Scan {scan_id}")
        for h in (details.get("hosts") or []):
            rows.append({
                "Scan_ID":        scan_id,
                "Scan_Nombre":    scan_name,
                #"Host_ID":        h.get("host_id"),
                "Hostname_IP":    h.get("hostname", ""),
                #"Critical":       h.get("critical", 0),
                #"High":           h.get("high", 0),
                #"Medium":         h.get("medium", 0),
                #"Low":            h.get("low", 0),
                #"Info":           h.get("info", 0),
                #"Total_Hallazgos": (
                #    h.get("critical", 0) + h.get("high", 0)
                #    + h.get("medium", 0) + h.get("low", 0)
                #    + h.get("info", 0)
                #),
                #"Score":          h.get("score", ""),
                #"Fecha_Reporte":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })

    df = pd.DataFrame(rows)
    if not df.empty:
        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        # Ordenar por scan y luego por severidad descendente
        df["_max_sev"] = df.apply(
            lambda r: min(
                sev_order[s] for s in ["Critical", "High", "Medium", "Low", "Info"]
                if r.get(s, 0) > 0
            ) if any(r.get(s, 0) > 0 for s in ["Critical", "High", "Medium", "Low"]) else 4,
            axis=1,
        )
        df = df.sort_values(["Scan_ID", "_max_sev"]).drop(columns="_max_sev").reset_index(drop=True)
    return df


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

    print("\n[1/4] Obteniendo lista de scans...")
    all_scans = api.list_scans()
    if not all_scans:
        print("  Error: no se obtuvo lista. Verifica credenciales.")
        return
    print(f"  {len(all_scans)} scans en total")

    print("\n[2/4] Filtrando scans de hoy...")
    scans_hoy = filter_scans_today(all_scans)
    scan_ids  = [s["id"] for s in scans_hoy]
    active_n  = sum(1 for s in scans_hoy if (s.get("status") or "").lower() in ACTIVE_STATUSES)
    print(f"  {len(scans_hoy)} scans hoy  |  {active_n} activos")

    print(f"\n[3/4] Obteniendo detalle de {len(scan_ids)} scans...")
    detalle_df = build_detalle_scan(scan_ids, api)
    hosts_df   = build_hosts(scan_ids, api)
    print(f"  {len(hosts_df)} hosts procesados")

    print(f"\n[4/4] Exportando a CSV...")

    detalle_df.to_csv(output_scans, index=False, encoding="utf-8")
    hosts_df.to_csv(output_hosts, index=False, encoding="utf-8")

    print("\n" + "=" * 55)
    print(f"  Scans CSV      : {output_scans}")
    print(f"  Hosts CSV      : {output_hosts}")
    print(f"  Detalle_Scan   : {len(detalle_df)} filas  x  {len(detalle_df.columns)} columnas")
    print(f"  Hosts          : {len(hosts_df)} filas  x  {len(hosts_df.columns)} columnas")
    if not hosts_df.empty:
        for sev in ["Critical", "High", "Medium", "Low"]:
            total = int(hosts_df[sev].sum()) if sev in hosts_df.columns else 0
            if total > 0:
                print(f"    {sev:<12}: {total}")
    print("=" * 55)


if __name__ == "__main__":
    main()
