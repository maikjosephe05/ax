# -*- coding: utf-8 -*-
"""
Created on Tue Sep 20 19:20:00 2023
Updated on June 25 11:50:00 2023
@edited by: WSARIAS
"""

import pandas as pd
from bs4 import BeautifulSoup
import os,json, requests, time
from tenable.sc import TenableSC
from tqdm import tqdm
import pprint
pd.options.mode.chained_assignment = None

archivo_json =os.path.abspath(os.path.dirname(os.path.abspath(__file__))+"/_Librerias/settings.json") 
with open(archivo_json, 'r') as sett:
    settings = json.load(sett)

# Configuración de llaves de acceso
sc = TenableSC('10.103.60.14')
ACCESS_KEY = settings['Credenciales']['SC']["ACCESS_KEY"]
SECRET_KEY = settings['Credenciales']['SC']["SECRET_KEY"]

sc.login(access_key=ACCESS_KEY, secret_key=SECRET_KEY)
headers = {
    "content-type": "application/json",
    "x-apikey": "accessKey={};secretKey={}".format(ACCESS_KEY, SECRET_KEY)
}

# Get Scan Detail (ID, Name)
def get_scan_id(nombre,day_range = None,url = 'https://10.103.60.14/rest/scanResult#'):
    nombres = []
    ids = []

    if day_range!=None:
        tiempo = int(time.time()-86400*day_range)
        params = {"startTime": tiempo}
        r = requests.get('{}'.format(url), verify=False, headers=headers, params=params,timeout=20)
    else:
        r = requests.get('{}'.format(url), verify=False, headers=headers,timeout=20)
    
    res = json.loads(r.text)["response"]["usable"]
    scans = pd.DataFrame(res)
    scan = scans[scans["name"].str.contains(nombre, na=False)]
    scan_completed = scan[scan["status"] == "Completed"]

    if not scan_completed.empty:
        print('-----------------------------------------------------------')
        print("[+] El siguiente inventario de escaneos fue identificado [+]\n")
        pprint.pprint(scan_completed)
        print('-----------------------------------------------------------')
        nombres = scan_completed['name'].tolist()
        ids = scan_completed['id'].tolist()
    else:
        print('-----------------------------------------------------------')
        print("[+] El siguiente inventario de escaneos fue identificado [+]\n")
        pprint.pprint(scan)
        print('-----------------------------------------------------------')
        print("[X] ERROR [X] El escaneo no pudo encontrarse o aun esta en Ejecucion")
        print('-----------------------------------------------------------')

    return ids,nombres

# Define text to be presented on "Plugin Output"
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
    data = {display_name: soup.find(tag).text if soup.find(tag) else 'N/A' for tag, display_name in tags_to_extract.items()}
    formatted_string = "\n".join([f"{key}: {value}" for key, value in data.items()])
    return formatted_string

def get_report(nombre_escaneo,day_range):
    id, name = get_scan_id(nombre_escaneo,day_range)
    for i in range(len(id)):
        data = []
        scan_id = int(id[i])
        scan_name = name[i]
        print('LB Details Download Initiated: {}_{} \n\n'.format(scan_name,scan_id))
        vulns = sc.analysis.scan(scan_id,('pluginID','>=','1000000'),tool='vulndetails',limit=10000)   
        total_elements = 100
        pbar = tqdm(total=total_elements)
        for vuln in vulns:
            plugin_text = vuln.get("pluginText", None)
            if plugin_text:
                formatted_text = parse_plugin_text(plugin_text)
                vuln["modPluginText"] = formatted_text
            data.append(vuln)
            total_elements = len(data)
            pbar.total = total_elements
            pbar.update(1)

        data_pd = pd.DataFrame(data)
        data_pd['llave'] = data_pd['dnsName'] + ' / ' + data_pd['ips']
        data_pd['severity'] = data_pd['severity'].apply(lambda x: x.get('name'))
        
        # INICIO Organizar parámetro de cumplimiento
        data_pd['compliance'] = data_pd['severity'].copy() 
        data_pd['compliance'].replace({"Info":"Passed","High":"Failed","Medium":"Warning"}, inplace = True)
        data_pd = data_pd[~data_pd['pluginName'].str.contains('Nessus Scan')]
        data_pd = data_pd[~data_pd['pluginName'].str.contains('CIS')]
        data_pd = data_pd[~data_pd['pluginName'].str.contains('Windows Server 2008 R2 is not installed')]
        data_pd = data_pd[~data_pd['pluginName'].str.contains('Compliance Check Test Error')]
        data_pd = data_pd[~data_pd['pluginName'].str.contains('Netstat')]
        # FIN Organizar parámetro de cumplimiento
        
        detail_vuln = data_pd[['pluginName','severity','ips','dnsName','modPluginText','compliance']]
        detail_vuln.columns = ["Plugin Name","Severity","IP Address","DNS Name","Plugin Output","Compliance"]
        detail_vuln.replace({'^-1': 'N/A'},regex=True,inplace=True)

        # INICIO Tabla resumen
        data_resum_pd = pd.DataFrame(data_pd[['llave','compliance']].value_counts())
        data_resum_pd = data_resum_pd.pivot_table(0, 'llave','compliance')
        
        # Controlar que todas las columnas existen, si no, crearla con valor cero.
        for col in ['Passed', 'Failed', 'Warning']:
            if col not in data_resum_pd.columns:
                data_resum_pd[col] = 0
        
        data_resum_pd['Total Controles']=data_resum_pd.sum(axis=1, numeric_only= True)
        data_resum_pd['% Cumplimiento']=data_resum_pd['Passed']/data_resum_pd['Total Controles']
        data_resum_pd.loc["Total"] = data_resum_pd.sum()
        data_resum_pd.at['Total','% Cumplimiento'] =data_resum_pd.at['Total','Passed']/data_resum_pd.at['Total','Total Controles']
        data_resum_pd.reset_index(inplace=True)
        data_resum_pd = data_resum_pd.reindex(columns=['llave','Passed','Failed','Warning','Total Controles','% Cumplimiento'])
        data_resum_pd.fillna(0, inplace=True)
        resume_vul=data_resum_pd[['llave','Passed','Failed','Warning','Total Controles','% Cumplimiento']]
        resume_vul.columns = ['DNS Name/IP Address','Passed','Failed','Warning','Total Controles','% Cumplimiento']
        # FIN Tabla Resumen

        s_name = scan_name.replace('/', '_')
        ruta =os.path.abspath(os.path.dirname(os.path.abspath(__file__))+"/Informes/{}_{}.xlsx".format(s_name,scan_id))
        documento = pd.ExcelWriter(ruta, engine='xlsxwriter',engine_kwargs={'options': {'strings_to_numbers': True, 'strings_to_urls': False}})
        resume_vul.to_excel(documento, sheet_name='Resumen LB', index=False)
        detail_vuln.to_excel(documento, sheet_name='Detalle LB', index=False)
        workbook  = documento.book
        worksheet = documento.sheets['Resumen LB'] 
        format = workbook.add_format({'num_format': '0%'})
        worksheet.set_column('F:F', None, format)
        documento.save()
        documento.close()
        documento.handles = None
        pbar.close()

def start_download(titulos,day_range):
    success = []
    failed = []
    for nombre_escaneo in titulos:
        try:
            get_report(nombre_escaneo,day_range)
            success.append(nombre_escaneo)
        except Exception as err:
            failed.append(nombre_escaneo)
            print(f"Unexpected {err=}, {type(err)=}")
            raise
        
    print("\n")
    print("Descargas satisfactorias: ",success)
    print("Descargas fallidas: ",failed)

#===========================================================
#===========================================================
day_range = 30
titulos = []
string = input('Ingrese el nombre del reporte: ')
string = string.replace('(', '\(').replace(')', '\)')
titulos.append(string)
start_download(titulos,day_range)
input("Presiona una tecla para finalizar")
#===========================================================
#===========================================================