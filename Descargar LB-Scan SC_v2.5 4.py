# -*- coding: utf-8 -*-

import pandas as pd
from bs4 import BeautifulSoup
import os, json, requests, time
from tenable.sc import TenableSC
from tqdm import tqdm
import pprint

pd.options.mode.chained_assignment = None

# ================= CONFIG =================
archivo_json = os.path.abspath(
    os.path.dirname(os.path.abspath(__file__)) + "/_Librerias/settings.json"
)

with open(archivo_json, 'r') as sett:
    settings = json.load(sett)

sc = TenableSC('')
ACCESS_KEY = settings['Credenciales']['SC']["ACCESS_KEY"]
SECRET_KEY = settings['Credenciales']['SC']["SECRET_KEY"]

sc.login(access_key=ACCESS_KEY, secret_key=SECRET_KEY)

headers = {
    "content-type": "application/json",
    "x-apikey": f"accessKey={ACCESS_KEY};secretKey={SECRET_KEY}"
}

# ================= SCANS =================
def get_scan_id(nombre, day_range=None, url=''):
    if day_range:
        tiempo = int(time.time() - 86400 * day_range)
        params = {"startTime": tiempo}
        r = requests.get(url, verify=False, headers=headers, params=params, timeout=20)
    else:
        r = requests.get(url, verify=False, headers=headers, timeout=20)

    res = json.loads(r.text)["response"]["usable"]
    scans = pd.DataFrame(res)

    scan = scans[scans["name"].str.contains(nombre, na=False)]
    scan_completed = scan[scan["status"] == "Completed"]

    if not scan_completed.empty:
        print("[+] Escaneos encontrados:")
        pprint.pprint(scan_completed)
        return scan_completed['id'].tolist(), scan_completed['name'].tolist()

    print("[X] No se encontraron escaneos completados")
    return [], []


# ================= PARSER =================
def parse_plugin_text(xml_data):
    tags_to_extract = {
        "cm:compliance-check-name": "Check Name",
        "cm:compliance-info": "Information",
        "cm:compliance-result": "Result",
        "cm:compliance-actual-value": "Actual Value",
        "cm:compliance-policy-value": "Policy Value",
        "cm:compliance-solution": "Solution",
        "cm:compliance-see-also": "See Also",
        "cm:compliance-reference": "Reference Information",
    }

    soup = BeautifulSoup(xml_data, 'lxml')

    data = {
        display: soup.find(tag).text if soup.find(tag) else 'N/A'
        for tag, display in tags_to_extract.items()
    }

    return "\n".join([f"{k}: {v}" for k, v in data.items()])


# ================= REPORT =================
def get_report(nombre_escaneo, day_range):
    ids, names = get_scan_id(nombre_escaneo, day_range)

    for i in range(len(ids)):
        data = []
        scan_id = int(ids[i])
        scan_name = names[i]

        print(f"Descargando: {scan_name} ({scan_id})")

        vulns = sc.analysis.scan(
            scan_id,
            ('pluginID', '>=', '1000000'),
            tool='vulndetails',
            limit=10000
        )

        for vuln in tqdm(vulns):
            if vuln.get("pluginText"):
                vuln["modPluginText"] = parse_plugin_text(vuln["pluginText"])
            data.append(vuln)

        df = pd.DataFrame(data)

        df['llave'] = df['dnsName'] + ' / ' + df['ips']
        df['severity'] = df['severity'].apply(lambda x: x.get('name'))

        df['compliance'] = df['severity'].replace({
            "Info": "Passed",
            "High": "Failed",
            "Medium": "Warning"
        })

        # filtros
        exclude = [
            'Nessus Scan',
            'CIS',
            'Windows Server 2008 R2 is not installed',
            'Compliance Check Test Error',
            'Netstat'
        ]

        for word in exclude:
            df = df[~df['pluginName'].str.contains(word, na=False)]

        detail = df[['pluginName','severity','ips','dnsName','modPluginText','compliance']]
        detail.columns = ["Plugin Name","Severity","IP Address","DNS Name","Plugin Output","Compliance"]

        summary = pd.crosstab(df['llave'], df['compliance'])

        for col in ['Passed','Failed','Warning']:
            if col not in summary.columns:
                summary[col] = 0

        summary['Total Controles'] = summary.sum(axis=1)
        summary['% Cumplimiento'] = summary['Passed'] / summary['Total Controles']

        summary.loc['Total'] = summary.sum(numeric_only=True)
        summary.at['Total','% Cumplimiento'] = (
            summary.at['Total','Passed'] / summary.at['Total','Total Controles']
        )

        summary.reset_index(inplace=True)
        summary.rename(columns={'llave':'DNS Name/IP Address'}, inplace=True)

        # ================= EXPORT SIMPLE =================
        ruta = os.path.abspath(
            os.path.dirname(__file__) +
            f"/Informes/{scan_name.replace('/','_')}_{scan_id}.xlsx"
        )

        with pd.ExcelWriter(ruta) as writer:
            summary.to_excel(writer, sheet_name='Resumen LB', index=False)
            detail.to_excel(writer, sheet_name='Detalle LB', index=False)

        print(f"Archivo generado: {ruta}")


# ================= RUN =================
def start_download(titulos, day_range):
    success, failed = [], []

    for nombre in titulos:
        try:
            get_report(nombre, day_range)
            success.append(nombre)
        except Exception as e:
            print(e)
            failed.append(nombre)

    print("OK:", success)
    print("FAILED:", failed)


day_range = 30
titulos = []

string = input('Ingrese el nombre del reporte: ')
titulos.append(string)

start_download(titulos, day_range)

input("Enter para finalizar")
