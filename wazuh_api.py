import tkinter as tk
import json
import requests
import urllib3
from base64 import b64encode

protocol = 'https'
host = '192.168.198.131'
port = 55000
token = ""
requests_headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'}
ventana = tk.Tk()
# Define el título de la ventana
ventana.title("Consulta Wazuh")
# Define las dimensiones de la ventana
ventana.geometry("1200x400")
# Crea el frame principal
frame_principal = tk.Frame(ventana)
frame_principal.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
# Crea los frames para cada elemento
frame_agentes = tk.Frame(frame_principal)
frame_agentes.pack(side=tk.LEFT, fill=tk.Y, padx=10)
frame_grupos = tk.Frame(frame_principal)
frame_grupos.pack(side=tk.LEFT, fill=tk.Y, padx=10)
frame_severidad = tk.Frame(frame_principal)
frame_severidad.pack(side=tk.LEFT, fill=tk.Y, padx=10)
frame_vulnerabilidades = tk.Frame(frame_principal)
frame_vulnerabilidades.pack(side=tk.LEFT, fill=tk.Y, padx=10)
frame_resultados = tk.Frame(frame_principal)
frame_resultados.pack(side=tk.TOP, fill=tk.BOTH, padx=10, pady=10, expand=True)
frame_entrada = tk.Frame(frame_principal)
frame_entrada.pack(side=tk.BOTTOM, fill=tk.BOTH, padx=10, pady=10, expand=True)
frame_entries = tk.Frame(frame_agentes)
frame_entries.pack(side=tk.BOTTOM, pady=10)
# Etiqueta para la lista de Agentes
lbl_agentes = tk.Label(frame_agentes, text="Agentes:")
lbl_agentes.pack(side=tk.TOP)
# Etiqueta para la lista de Grupos
lbl_grupos = tk.Label(frame_grupos, text="Grupos:")
lbl_grupos.pack(side=tk.TOP)
# Etiqueta para el menú de Severidad
lbl_severidad = tk.Label(frame_severidad, text="Severidad:")
lbl_severidad.pack(side=tk.TOP)
#Etiqueta para la lista de Vulnerabilidades
lbl_vulnerabilidades = tk.Label(frame_vulnerabilidades, text="Vulnerabilidades:")
lbl_vulnerabilidades.pack(side=tk.TOP)
#Etiqueta para resultados
lbl_vulnerabilidades = tk.Label(frame_resultados, text="Resultados de consultas:")
lbl_vulnerabilidades.pack(side=tk.TOP)
#Etiqueta para los campos del agente que se desea añadir
name_label = tk.Label(frame_entries, text="Nombre:")
name_label.grid(row=0, column=0)
name_entry = tk.Entry(frame_entries)
name_entry.grid(row=0, column=1)
id_label = tk.Label(frame_entries, text="ID:")
id_label.grid(row=1, column=0)
id_entry = tk.Entry(frame_entries)
id_entry.grid(row=1, column=1)
ip_label = tk.Label(frame_entries, text="Dirección IP:")
ip_label.grid(row=2, column=0)
ip_entry = tk.Entry(frame_entries)
ip_entry.grid(row=2, column=1)

# Define las opciones de los agentes ,los grupos y vulnerabilidades
opciones_agentes = tk.StringVar(value=[])
opciones_grupos = tk.StringVar(value=[])
opciones_vulnerabilidades = [] # una lista vacía
opciones_vulnerabilidades_str = tk.StringVar(value=",".join(opciones_vulnerabilidades)) # convertir la lista en una cadena y asignarla a una variable de tipo StringVar
# Define las opciones del menú de Severidad
opciones_severidad = ["Todas", "Críticas", "Altas", "Medias", "Bajas", "None"]

# Variables para almacenar las selecciones de las listas
agente_seleccionado = tk.StringVar()
grupo_seleccionado = tk.StringVar()
severidad_seleccionado = tk.StringVar(value="Seleccione un nivel de severidad")
vulnerabilidad_seleccionada = tk.StringVar(value="Seleccione una vulnerabilidad")

# Función para actualizar la selección del agente
def actualizar_agente(*args):
    seleccion = lista_agentes.curselection()
    if seleccion:
        indice = seleccion[0]
        valor = lista_agentes.get(indice)
        agente_seleccionado.set(valor)

# Función para actualizar la selección del grupo
def actualizar_grupo(*args):
    seleccion = lista_grupos.curselection()
    if seleccion:
        indice = seleccion[0]
        valor = lista_grupos.get(indice)
        grupo_seleccionado.set(valor)

# Función para actualizar la selección de severidad
def actualizar_severidad(*args):
    seleccion = menu_severidad.curselection()
    if seleccion:
        indice = seleccion[0]
        valor = menu_severidad.get(indice)
        severidad_seleccionado.set(valor)

# Función para actualizar la selección de vulnerabilidad
def actualizar_vulnerabilidad(*args):
    seleccion = menu_vulnerabilidades.curselection()
    if seleccion:
        indice = seleccion[0]
        valor = menu_vulnerabilidades.get(indice)
        vulnerabilidad_seleccionada.set(valor)

# Función para obtener la selección actual de ambas listas
def consultar_severidad(*args):
    global protocol
    global host 
    global port
    global requests_headers
    severidad = severidad_seleccionado.get()
    resultados_text.delete("1.0", tk.END)
    
    if severidad == "Todas":
        resultados_text.insert(tk.END, "Severidad seleccionada: " + severidad + "\n")
        todas = requests.get(f"{protocol}://{host}:{port}/vulnerability/001?q=severity=Critical,severity=High,severity=Medium,severity=Low&pretty=true", headers=requests_headers, verify=False)
        todas.raise_for_status()
        datos = json.loads(todas.text)
        try: 
            if 'data' in datos and 'affected_items' in datos['data']:
                for item in datos['data']['affected_items']:
                    if 'title' in item:
                        resultados_text.insert(tk.END, item['title'] + "\n")
        except requests.exceptions.HTTPError as error:
            print(f"Error al hacer la petición: {error}")

    elif severidad =="Críticas":
        resultados_text.insert(tk.END, "Severidad seleccionada: " + severidad + "\n")
        criticas = requests.get(f"{protocol}://{host}:{port}/vulnerability/001?q=severity=Critical,&pretty=true", headers=requests_headers, verify=False)
        criticas.raise_for_status()
        datos = json.loads(criticas.text)
        try: 
            if 'data' in datos and 'affected_items' in datos['data']:
                for item in datos['data']['affected_items']:
                    if 'title' in item:
                        resultados_text.insert(tk.END, item['title'] + "\n")
        except requests.exceptions.HTTPError as error:
            print(f"Error al hacer la petición: {error}")


    elif severidad == "Altas":
        resultados_text.insert(tk.END, "Severidad seleccionada: " + severidad + "\n")
        altas = requests.get(f"{protocol}://{host}:{port}/vulnerability/001?q=severity=High&pretty=true", headers=requests_headers, verify=False)
        altas.raise_for_status()
        datos = json.loads(altas.text)
        try: 
            if 'data' in datos and 'affected_items' in datos['data']:
                for item in datos['data']['affected_items']:
                    if 'title' in item:
                        resultados_text.insert(tk.END, item['title'] + "\n")
        except requests.exceptions.HTTPError as error:
            print(f"Error al hacer la petición: {error}")

    elif severidad == "Medias": 
        resultados_text.insert(tk.END, "Severidad seleccionada: " + severidad + "\n")
        medias = requests.get(f"{protocol}://{host}:{port}/vulnerability/001?q=severity=Medium&pretty=true", headers=requests_headers, verify=False)
        medias.raise_for_status()
        datos = json.loads(medias.text)
        try: 
            if 'data' in datos and 'affected_items' in datos['data']:
                for item in datos['data']['affected_items']:
                    if 'title' in item:
                        resultados_text.insert(tk.END, item['title'] + "\n")
        except requests.exceptions.HTTPError as error:
            print(f"Error al hacer la petición: {error}")

    elif severidad == "Bajas":
        resultados_text.insert(tk.END, "Severidad seleccionada: " + severidad + "\n")
        bajas = requests.get(f"{protocol}://{host}:{port}/vulnerability/001?q=severity=Low&pretty=true", headers=requests_headers, verify=False)
        bajas.raise_for_status()
        datos = json.loads(bajas.text)
        try: 
            if 'data' in datos and 'affected_items' in datos['data']:
                for item in datos['data']['affected_items']:
                    if 'title' in item:
                        resultados_text.insert(tk.END, item['title'] + "\n")
        except requests.exceptions.HTTPError as error:
            print(f"Error al hacer la petición: {error}")
    else:
        severidad = severidad

    #resultados_text.insert(tk.END, "Agente seleccionado: " + agente + "\n")
    #resultados_text.insert(tk.END, "Grupo seleccionado: " + grupo + "\n")
    #resultados_text.insert(tk.END, "Vulnerabilidad seleccionada: " + vulnerabilidad + "\n")

    print("Severidad seleccionada:", severidad)

def consultar_cve (*args):
    global protocol
    global host 
    global port
    global requests_headers
    vulnerabilidad = vulnerabilidad_seleccionada.get()
    resultados_text.delete("1.0", tk.END)

    ids = []
    response = requests.get(f"{protocol}://{host}:{port}/agents?pretty=true", headers=requests_headers, verify=False)
    resp = json.loads(response.content.decode())['data']['affected_items'] 
    for i in resp:
        nombre = i['id'] # Obtener el nombre del elemento actual
        ids.append(nombre)

    for agente in ids:
        common_vul = requests.get(f"{protocol}://{host}:{port}/vulnerability/{agente}?q=cve={vulnerabilidad}&limit=800&pretty=true", headers=requests_headers, verify=False)
        #print(common_vul.text)
        data = json.loads(common_vul.text)
        affected_items = data.get("data", {}).get("affected_items", [])
        if affected_items:
            # Extrae los elementos que necesitas del diccionario
            for item in affected_items:
                item = affected_items[0]
                name = item.get('name')
                updated = item.get('updated')
                version = item.get('version')
                status = item.get('status')
                severity = item.get('severity')
                resultados_text.insert(tk.END,vulnerabilidad + "\n" + "Nombre: " + name + "\n" + "Actualización: "+ updated + "\n" + "Versión: " + version + "\n"+ "Estado: " + status + "\n" + "Severidad: "+ severity + "\n")
                print("Severidad seleccionada:", vulnerabilidad)
                resultados_text.insert(tk.END, f"\n-------------------\n\n") 

    resultados_text.insert(tk.END,"Agentes con la vulnerabilidad "+ vulnerabilidad +" : " + "\n")
    
    for agent in ids:
        vul_search = requests.get(f"{protocol}://{host}:{port}/vulnerability/{agent}?search={vulnerabilidad}", headers=requests_headers, verify=False)
        data = json.loads(vul_search.text)
        affected_items = data.get("data", {}).get("affected_items", [])
        if affected_items:
            resultados_text.insert(tk.END,"Agente: " + agent + "\n")
        else: 
            resultados_text.insert(tk.END, f"\nNo hay coicidencias con {agent}\n\n")   

def consultar_agente (*args):
    global protocol
    global host 
    global port
    global requests_headers
    agente = agente_seleccionado.get()
    if agente:
        resultados_text.delete("1.0", tk.END)
        solicitud = requests.get(f"{protocol}://{host}:{port}/agents?select=name&select=ip&select=status&select=os.name&select=os.version&select=os.platform&search={agente}&pretty=true", headers=requests_headers, verify=False)
        data =json.loads(solicitud.text)
        name = data['data']['affected_items'][0].get('os', {}).get('name', 'N/A')
        platform = data['data']['affected_items'][0].get('os', {}).get('platform', 'N/A')
        version = data['data']['affected_items'][0].get('os', {}).get('version', 'N/A')
        ip = data['data']['affected_items'][0]['ip']
        status = data['data']['affected_items'][0]['status']
        id = data['data']['affected_items'][0]['id']
        resultados_text.insert(tk.END,agente + "\n" + "Sistema operativo: " + name + "\n" + "Plataforma: "+ platform + "\n" + "Versión: " + version + "\n"+ "Estado: " + status + "\n" + "IP: "+ ip + "\n" + "ID: "+ id + "\n")
    else: 
        resultados_text.insert(tk.END, "No hay agente seleccionado.\n")
def consultar_grupos(*args):
    global protocol
    global host 
    global port
    global requests_headers
    grupo = grupo_seleccionado.get()
    if grupo:
        resultados_text.delete("1.0", tk.END)
        solicitud = requests.get(f"{protocol}://{host}:{port}/groups?search={grupo}&pretty=true", headers=requests_headers, verify=False)
        data =json.loads(solicitud.text)
        if data['data']['affected_items']:
            count = data['data']['affected_items'][0]['count']
            resultados_text.insert(tk.END,grupo + "\n" + "Número de agentes: " + str(count) + "\n")
        else:
            resultados_text.insert(tk.END, "No se encontraron agentes el el grupo.\n")
    else: 
        resultados_text.insert(tk.END, "No hay grupo seleccionado.\n")


def buscar(*args):
    global protocol
    global host 
    global port
    global requests_headers
    resultados_text.delete("1.0", tk.END)
    palabra_clave = entrada.get()
    if palabra_clave:
        resultados_text.delete("1.0", tk.END)
        resultados_text.insert(tk.END,"Búsqueda de vulnerabilidades para: " + palabra_clave + "\n") 
        ids = []
        response = requests.get(f"{protocol}://{host}:{port}/agents?pretty=true", headers=requests_headers, verify=False)
        resp = json.loads(response.content.decode())['data']['affected_items'] 
        for i in resp:
            id = i['id'] # Obtener el nombre del elemento actual
            ids.append(id)

        for agent in ids:
            busqueda_clave = requests.get(f"{protocol}://{host}:{port}/vulnerability/{agent}?search={palabra_clave}&pretty=true", headers=requests_headers, verify=False)
            data = json.loads(busqueda_clave.text)
            affected_items = data.get("data", {}).get("affected_items", [])
            if affected_items:
                resultados_text.insert(tk.END,"Coincidencias para agente: " + agent + "\n")
                for item in affected_items:
                    item = affected_items[0]
                    name = item.get("name")
                    updated = item.get("updated")
                    version = item.get("version")
                    status = item.get("status")
                    severity = item.get("severity")
                    resultados_text.insert(tk.END,f"\n\nNombre: {name}\nUpdated: {updated}\nVersión: {version}\nEstado: {status}\nSeveridad: {severity}\n")
            else: 
                resultados_text.insert(tk.END, f"\nNo hay coicidencias con el agente {agent}\n\n")    
    

#Función para actualizar la selección de la vulnerabilidad
def actualizar_vulnerabilidad(*args):
    seleccion = menu_vulnerabilidades.curselection()
    if seleccion:
        indice = seleccion[0]
    valor = menu_vulnerabilidades.get(indice)
    vulnerabilidad_seleccionada.set(valor)

# Función para conectarse a la API
def conectarse(*args):
    # Disable insecure https warnings (for self-signed SSL certificates)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    # Configuration
    global token
    global requests_headers 
    global protocol 
    global host
    global port 
    user = 'wazuh'
    password = 'wazuh'
    login_endpoint = 'security/user/authenticate'
    login_url = f"{protocol}://{host}:{port}/{login_endpoint}"
    basic_auth = f"{user}:{password}".encode()
    login_headers = {'Content-Type': 'application/json','Authorization': f'Basic {b64encode(basic_auth).decode()}'}
    print("\nLogin request ...\n")

    response = requests.post(login_url, headers=login_headers, verify=False)
    token = json.loads(response.content.decode())['data']['token']
    #print(token)

    # New authorization header with the JWT token we got
    requests_headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'}
    print("\n- API calls with TOKEN environment variable ...\n")
    ids=[]
    opciones = []
    #Solicitud y proceso para obtener y mostrar los agentes y grupos
    response = requests.get(f"{protocol}://{host}:{port}/agents?pretty=true", headers=requests_headers, verify=False) # Solicitud de los agentes
    #print(response.text) #Imprime el Json
    resp = json.loads(response.content.decode())['data']['affected_items'] #Así se convierte y maneja como un objeto por bloques 
    for i in resp:
        nombre = i['name'] # Obtener el nombre del elemento actual
        id = i['id'] # Obtener el nombre del elemento actual
        ids.append(id)
        opciones.append(nombre)

    grupos_opc = []
    respuesta = requests.get(f"{protocol}://{host}:{port}/groups?pretty=true", headers=requests_headers, verify=False)
    data =json.loads(respuesta.text)
    grupos = data['data']['affected_items']
    for group in grupos:
        grp = group['name'] 
        grupos_opc.append(grp)

    opciones_agentes.set(opciones) # Asignar la cadena al objeto opciones_agentes para actualizar la vista
    #grupos_str = ", ".join(list(set(grupos_opc))) # Convertir la lista de grupos en una cadena separada por comas
    opciones_grupos.set(grupos_opc) # Asignar la cadena al objeto opciones_grupos para actualizar la vista
    print(opciones_agentes.get()) # Imprimir la lista completa de nombres
    print(list(set(grupos_opc)))
    vulnerabilidades = []
    cves = []
    # Solicitud para las severidades existentes
    for agent in ids:
        response2 = requests.get(f"{protocol}://{host}:{port}/vulnerability/{agent}?q=severity=Critical,severity=High,severity=Medium,severity=Low&pretty=true", headers=requests_headers, verify=False)
        data2 = json.loads(response2.text)
        affected_items = data2.get("data", {}).get("affected_items", [])
        if affected_items:
            for item in affected_items:
                if 'cve' in item:
                 cves = item.get('cve')
                 if isinstance(cves, list):
                    for cve in cves:
                        if cve not in vulnerabilidades:
                            vulnerabilidades.append(cve)
                 else:
                    if cves not in vulnerabilidades:
                        vulnerabilidades.append(cves)
    opciones_vulnerabilidades = vulnerabilidades
    opciones_vulnerabilidades_str.set(" ".join(opciones_vulnerabilidades)) # actualizar el valor de la variable StringVar con la nueva lista de opciones
    
    menu_vulnerabilidades['menu'].delete(0, 'end')
    for vulnerabilidad in opciones_vulnerabilidades:
        menu_vulnerabilidades['menu'].add_command(label=vulnerabilidad, command=lambda v=vulnerabilidad: vulnerabilidad_seleccionada.set(v))
    print(opciones_vulnerabilidades) # Imprimir la lista completa de nombres

def mostrar_top_vul (*args):
    vuln_counts = {}
    global opciones_vulnerabilidades_str
    opciones_vulnerabilidades = opciones_vulnerabilidades_str.get().split()
    for vuln in opciones_vulnerabilidades:
        if vuln in vuln_counts:
            vuln_counts[vuln] += 1
        else:
            vuln_counts[vuln] = 1
# Ordenar las vulnerabilidades por el número de ocurrencias y mostrar las 10 más comunes
    top_vulns = sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    print("Top 10 vulnerabilidades:")
    resultados_text.insert(tk.END,"Top 10 vulnerabilidades:\n")
    for i, (vuln, count) in enumerate(top_vulns):
        print(f"{i+1}. {vuln}: {count} ocurrencias")
        resultados_text.insert(tk.END,f"{i+1}. {vuln}: {count} ocurrencias" + "\n")

def mostrar_top_ag (*args):
    # Crear un diccionario para contar el número de vulnerabilidades por agente
    agent_vuln_counts = {}
    ids = []
    response = requests.get(f"{protocol}://{host}:{port}/agents?pretty=true", headers=requests_headers, verify=False)
    resp = json.loads(response.content.decode())['data']['affected_items'] 
    for i in resp:
        id = i['id'] # Obtener el nombre del elemento actual
        ids.append(id)
    # Iterar sobre la lista de vulnerabilidades y contar el número de ocurrencias por agente
    global opciones_vulnerabilidades_str
    opciones_vulnerabilidades = opciones_vulnerabilidades_str.get().split()
    for vuln in opciones_vulnerabilidades:
        affected_agents = set()
        for agent in ids:
            response = requests.get(f"{protocol}://{host}:{port}/vulnerability/{agent}?q=cve={vuln}&pretty=true", headers=requests_headers, verify=False)
            data = json.loads(response.text)
            affected_items = data.get("data", {}).get("affected_items", [])
            if affected_items:
                affected_agents.add(agent)
        for agent in affected_agents:
            agent_vuln_counts[agent] = agent_vuln_counts.get(agent, 0) + 1
    # Ordenar los agentes por el número de vulnerabilidades y mostrar los 10 más comunes
    top_agents = sorted(agent_vuln_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    print("Top 10 agentes con más vulnerabilidades:")
    for i, (agent, count) in enumerate(top_agents):
        print(f"{i+1}. {agent}: {count} vulnerabilidades")

def ir_extras (*args):
 def consultar_estado(*args):
    global protocol
    global host 
    global port
    global requests_headers
    resul_text.delete("1.0", tk.END)
    wazuh_status = requests.get(f"{protocol}://{host}:{port}/manager/status?pretty=true", headers=requests_headers, verify=False)
    data = json.loads(wazuh_status.text)
    # Acceder a los elementos dentro del objeto
    affected_items = data['data']['affected_items'][0]
    # Imprimir los elementos
    resul_text.insert(tk.END,"Estado del servidor:" + "\n")
    for item in affected_items:
        resul_text.insert(tk.END,"-------" + "\n")
        resul_text.insert(tk.END,item + ": " + affected_items[item] + "\n")

 def ver_configuracion(*args):
    global protocol
    global host 
    global port
    global requests_headers
    resul_text.delete("1.0", tk.END)
    st_conf = requests.get(f"{protocol}://{host}:{port}/manager/configuration?pretty=true", headers=requests_headers, verify=False)
    data = json.loads(st_conf.text)
    global_data = data['data']['affected_items'][0].get('global', {})
    alerts_data = data['data']['affected_items'][0].get('alerts', {})
    vulnerability_detector_data = data['data']['affected_items'][0].get('vulnerability-detector',{})
    sca_data = data['data']['affected_items'][0].get('sca',{})
    provider = vulnerability_detector_data['provider']
    resul_text.insert(tk.END,"\n" + "Configuración global:" + "\n" + "\n")
    for item in global_data:
        if isinstance(global_data[item], list):
            resul_text.insert(tk.END,f"{item}: {', '.join(global_data[item])}\n")
        else:
            resul_text.insert(tk.END,f"{item}: {global_data[item]}\n")
    resul_text.insert(tk.END,"\n" + "Configuración de alertas:" + "\n" + "\n")
    for item in alerts_data:
        resul_text.insert(tk.END,item + ": " + alerts_data[item] + "\n")
    resul_text.insert(tk.END,"\n" + "Configuración de detector de vulnerabilidades:" + "\n" + "\n")
    for item in vulnerability_detector_data:
        if item == "provider":
         resul_text.insert(tk.END, "proveedor:" + "\n")
         for key, value in provider.items():
             resul_text.insert(tk.END, f"{key}: {value}\n")   
        else:    
            values = str(vulnerability_detector_data[item])
            resul_text.insert(tk.END, f"{item}: {values}\n")
    resul_text.insert(tk.END,"\n" + "Configuración sca:" + "\n" + "\n")
    for item in sca_data:
        resul_text.insert(tk.END,item + ": " + sca_data[item] + "\n")
   
 def ver_logs (*args):
    global protocol
    global host 
    global port
    global requests_headers
    st_logs = requests.get(f"{protocol}://{host}:{port}/manager/logs?pretty=true", headers=requests_headers, verify=False)
    data = json.loads(st_logs.text)
    eventos = data['data']['affected_items']
    resul_text.delete("1.0", tk.END)
    for evento in eventos:
        resul_text.insert(tk.END, f"Timestamp: {evento['timestamp']}\n")
        resul_text.insert(tk.END, f"Tag: {evento['tag']}\n")
        resul_text.insert(tk.END, f"Level: {evento['level']}\n")
        resul_text.insert(tk.END, f"Description: {evento['description']}\n\n")

 def ver_resumen (*args):
    global protocol
    global host 
    global port
    global requests_headers
    resul_text.delete("1.0", tk.END)
    st_logs = requests.get(f"{protocol}://{host}:{port}/manager/logs/summary?pretty=true", headers=requests_headers, verify=False)
    data = json.loads(st_logs.text) 
    items = data['data']['affected_items']
    for item in items:
        for key in item.keys():
            values = item[key]
            resul_text.insert(tk.END, f"{key}\n")
        for k, v in values.items():
            resul_text.insert(tk.END, f"\t{k}: {v}\n")
        resul_text.insert(tk.END, f"\n")

 def traer_grupos (*args):
    global protocol
    global host 
    global port
    global requests_headers
    resul_text.delete("1.0", tk.END)
    respuesta = requests.get(f"{protocol}://{host}:{port}/groups?pretty=true", headers=requests_headers, verify=False)
    data =json.loads(respuesta.text)
    grupos = data['data']['affected_items']
    i = 1
    for group in grupos:
        bandera = str(i)
        resul_text.insert(tk.END,bandera + ": " + f"{group['name']}\n")
        i = i +1;

 def traer_tareas(*args):
    global protocol
    global host 
    global port
    global requests_headers
    resul_text.delete("1.0", tk.END)
    respuesta = requests.get(f"{protocol}://{host}:{port}/tasks/status?pretty=true", headers=requests_headers, verify=False)
    data =json.loads(respuesta.text)
    if data['message'] == "No status was returned":
        resul_text.insert(tk.END,"No se encontraron tareas activas" + "\n")
    else: 
        info = data['data']['affected_items']
        for item in info:
            resul_text.insert(tk.END,item + ": " + info[item] + "\n")

 def info_hard (*args):
    global protocol
    global host 
    global port
    global requests_headers
    resul_text.delete("1.0", tk.END)
    ids = []
    response = requests.get(f"{protocol}://{host}:{port}/agents?pretty=true", headers=requests_headers, verify=False)
    resp = json.loads(response.content.decode())['data']['affected_items'] 
    for i in resp:
        nombre = i['id'] # Obtener el nombre del elemento actual
        ids.append(nombre)

    for agent in ids:
        respuesta = requests.get(f"{protocol}://{host}:{port}/syscollector/{agent}/hardware?pretty=true", headers=requests_headers, verify=False)
        data =json.loads(respuesta.text)
        if "data" in data:
            cpu = data['data']['affected_items'][0].get('cpu', 'N/A')
            ram = data['data']['affected_items'][0].get('ram', 'N/A')
            scan = data['data']['affected_items'][0].get('scan', 'N/A')
            resul_text.insert(tk.END, f"\n\nAgente: {agent}\n")
            resul_text.insert(tk.END,"\n" + "CPU:" + "\n")
            for item in cpu:
                resul_text.insert(tk.END,item + ": " + str(cpu[item]) + "\n")
            resul_text.insert(tk.END,"\n" + "RAM:" + "\n")
            for item in ram:
                resul_text.insert(tk.END,item + ": " + str(ram[item]) + "\n")
            resul_text.insert(tk.END,"\n" + "Escaneo:" + "\n")
            for item in scan:
                resul_text.insert(tk.END,item + ": " + str(scan[item]) + "\n")
        else: 
            resul_text.insert(tk.END, f"\n\nNo hay información para el agente {agent}\n\n")


 def traer_hotfix (*args):
    global protocol
    global host 
    global port
    global requests_headers
    resul_text.delete("1.0", tk.END)
    ids = []
    response = requests.get(f"{protocol}://{host}:{port}/agents?pretty=true", headers=requests_headers, verify=False)
    resp = json.loads(response.content.decode())['data']['affected_items'] 
    for i in resp:
        nombre = i['id'] # Obtener el nombre del elemento actual
        ids.append(nombre)

    for agent in ids:    
        inv_hotfixes = requests.get(f"{protocol}://{host}:{port}/syscollector/{agent}/hotfixes?pretty=true", headers=requests_headers, verify=False)
        data = json.loads(inv_hotfixes.text)
        if "data" in data:
            affected_items = data['data']['affected_items']
            for item in affected_items:
                hotfix = item['hotfix']
                scan_time = item['scan_time']
                agent_id = item['agent_id']
                resul_text.insert(tk.END, f'Hotfix: {hotfix}\nTiempo de escaneo: {scan_time}\nID agente: {agent_id}\n\n')
        else: 
            resul_text.insert(tk.END, f"No hay Hotfixes para el agente {agent}\n\n")

 def traer_ip (*args):
    global protocol
    global host 
    global port
    global requests_headers
    resul_text.delete("1.0", tk.END)
    ids = []
    response = requests.get(f"{protocol}://{host}:{port}/agents?pretty=true", headers=requests_headers, verify=False)
    resp = json.loads(response.content.decode())['data']['affected_items'] 
    for i in resp:
        nombre = i['id'] # Obtener el nombre del elemento actual
        ids.append(nombre)
    
    for agent in ids:
        inv_netaddr = requests.get(f"{protocol}://{host}:{port}/syscollector/{agent}/netaddr?pretty=true", headers=requests_headers, verify=False)
        data = json.loads(inv_netaddr.text)
        if "data" in data:
            data = data["data"]["affected_items"]
            for item in data:
                proto = item["proto"]
                address = item["address"]
                iface = item["iface"]
                agent_id = item["agent_id"]
                resul_text.insert(tk.END, f"Protocolo: {proto}\nDirección: {address}\nIface: {iface}\nID agente: {agent_id}\n\n")
        else: 
            resul_text.insert(tk.END, f"No hay configuraciones para el agente {agent}\n\n")

 def traer_interfaz(*args):
    global protocol
    global host 
    global port
    global requests_headers
    resul_text.delete("1.0", tk.END)
    ids = []
    response = requests.get(f"{protocol}://{host}:{port}/agents?pretty=true", headers=requests_headers, verify=False)
    resp = json.loads(response.content.decode())['data']['affected_items'] 
    for i in resp:
        nombre = i['id'] # Obtener el nombre del elemento actual
        ids.append(nombre)

    for agent in ids:
        inv_netiface = requests.get(f"{protocol}://{host}:{port}/syscollector/{agent}/netiface?pretty=true", headers=requests_headers, verify=False)
        data = json.loads(inv_netiface.text)
        if "data" in data:
            data = data["data"]["affected_items"]
            for item in data:
                mtu = item.get('mtu', 'No disponible')
                type = item.get('type', 'No disponible')
                adapter = item.get('adapter', 'No disponible')
                name = item.get('name', 'No disponible')
                mac = item.get('mac', 'No disponible')
                state = item.get('state', 'No disponible')
                agent_id = item.get('agent_id', 'No disponible')
                resul_text.insert(tk.END, f"MTU: {mtu}\nTipo: {type}\nAdaptador: {adapter}\nNombre: {name}\nmac: {mac}\nEstado: {state}\nID agente: {agent_id}\n\n")
        else: 
            resul_text.insert(tk.END, f"No hay configuraciones para el agente {agent}\n\n")
            
 def traer_ruteo(*args):
    global protocol
    global host 
    global port
    global requests_headers
    resul_text.delete("1.0", tk.END)
    ids = []
    response = requests.get(f"{protocol}://{host}:{port}/agents?pretty=true", headers=requests_headers, verify=False)
    resp = json.loads(response.content.decode())['data']['affected_items'] 
    for i in resp:
        nombre = i['id'] # Obtener el nombre del elemento actual
        ids.append(nombre)

    for agent in ids:
        inv_netproto = requests.get(f"{protocol}://{host}:{port}/syscollector/{agent}/netproto?pretty=true", headers=requests_headers, verify=False)
        data = json.loads(inv_netproto.text)
        if "data" in data:
            data = data["data"]["affected_items"]
            resul_text.insert(tk.END, f"Agente: {agent}\n\n")
            for item in data:
                dhcp = item['dhcp']
                iface = item['iface']
                type = item['type']
                gate = item['gateway']
                agent_id = item['agent_id']
                resul_text.insert(tk.END, f"DHCP: {dhcp}\nIface: {iface}\nTipo: {type}\nGateway: {gate}\nID agente: {agent_id}\n\n")
        else: 
            resul_text.insert(tk.END, f"No hay configuración para el agente {agent}\n\n")
            

 def traer_so(*args):
    global protocol
    global host 
    global port
    global requests_headers
    resul_text.delete("1.0", tk.END)
    ids = []
    response = requests.get(f"{protocol}://{host}:{port}/agents?pretty=true", headers=requests_headers, verify=False)
    resp = json.loads(response.content.decode())['data']['affected_items'] 
    for i in resp:
        nombre = i['id'] # Obtener el nombre del elemento actual
        ids.append(nombre)

    for agent in ids:
        inv_os = requests.get(f"{protocol}://{host}:{port}/syscollector/{agent}/os?pretty=true", headers=requests_headers, verify=False)
        data = json.loads(inv_os.text)
        if inv_os.status_code == 200:
            if "data" in data:
                os_data = inv_os.json()["data"]['affected_items']
                # Iterar sobre cada sistema operativo e imprimir la información
                resul_text.insert(tk.END, f"Agente: {agent}\n\n")
                for os in os_data:
                    name = os['hostname']
                    agent_id = os['agent_id']
                    resul_text.insert(tk.END, f"Equipo: {name}\nID agente: {agent_id}\n")
                    os_info = os.get('os', 'N/A')
                    if os_info:
                        os = os_info['name']
                        version = os_info['version']
                        resul_text.insert(tk.END, f"OS: {os}\nVersión: {version}\n\n")
                        print("-----")
            else: 
                resul_text.insert(tk.END, f"\n\nNo hay OS detectado para el agente {agent}\n\n")
        else:
            print(f"Error {inv_os.status_code}: {inv_os.json().get('message', 'Unknown error')}")
    

 def traer_pack (*args):
    global protocol
    global host 
    global port
    global requests_headers
    resul_text.delete("1.0", tk.END)
    ids = []
    response = requests.get(f"{protocol}://{host}:{port}/agents?pretty=true", headers=requests_headers, verify=False)
    resp = json.loads(response.content.decode())['data']['affected_items'] 
    for i in resp:
        nombre = i['id'] # Obtener el nombre del elemento actual
        ids.append(nombre)

    for agent in ids:
        inv_packages = requests.get(f"{protocol}://{host}:{port}/syscollector/{agent}/packages?pretty=true&limit=50", headers=requests_headers, verify=False)
        data = json.loads(inv_packages.text)
        if "data" in data:
            data = data["data"]["affected_items"]
            resul_text.insert(tk.END, f"Agente: {agent}\n\n")
            for item in data:
                name = item.get('name', 'Desconocido')
                version = item.get('version', 'Desconocido')
                vendor = item.get('vendor', 'Desconocido')
                agent_id = item['agent_id']
                resul_text.insert(tk.END, f"Nombre: {name}\nVersion: {version}\nProveedor: {vendor}\nID agente: {agent_id}\n\n")
        else: 
            resul_text.insert(tk.END, f"\n\nNo hay paquetes para el agente {agent}\n\n")

 def traer_puertos(*args):
    global protocol
    global host 
    global port
    global requests_headers
    resul_text.delete("1.0", tk.END)
    ids = []
    response = requests.get(f"{protocol}://{host}:{port}/agents?pretty=true", headers=requests_headers, verify=False)
    resp = json.loads(response.content.decode())['data']['affected_items'] 
    for i in resp:
        nombre = i['id'] # Obtener el nombre del elemento actual
        ids.append(nombre)
    
    for agent in ids:
        inv_ports = requests.get(f"{protocol}://{host}:{port}/syscollector/{agent}/ports?pretty=true", headers=requests_headers, verify=False)
        data = json.loads(inv_ports.text)
        if "data" in data:
            data = data["data"]["affected_items"]
            resul_text.insert(tk.END, f"Agente: {agent}\n\n")
            for item in data:
                local_ip = item["local"].get("ip", "Desconocido")
                protocolo = item.get("protocol", "Desconocido")
                state = item.get("state", "Desconocido")
                agent_id = item.get("agent_id", "Desconocido")
                resul_text.insert(tk.END, f"Local IP: {local_ip}\nProtocol: {protocolo}\nState: {state}\nAgent ID: {agent_id}\n\n")
        else: 
            resul_text.insert(tk.END, f"\n\nNo se encontraron puertos para el agente {agent}\n\n")

 def traer_procesos(*args):
    global protocol
    global host 
    global port
    global requests_headers
    resul_text.delete("1.0", tk.END)
    ids = []
    response = requests.get(f"{protocol}://{host}:{port}/agents?pretty=true", headers=requests_headers, verify=False)
    resp = json.loads(response.content.decode())['data']['affected_items'] 
    for i in resp:
        nombre = i['id'] # Obtener el nombre del elemento actual
        ids.append(nombre)
    
    for agent in ids:
        inv_processes = requests.get(f"{protocol}://{host}:{port}/syscollector/{agent}/processes?pretty=true&limit=50", headers=requests_headers, verify=False)
        data = json.loads(inv_processes.text)
        if "data" in data:
            data = data["data"]["affected_items"]
            resul_text.insert(tk.END, f"\nAgente: {agent}\n\n")
            for item in data:
                name = item.get("name", "Desconocido")
                priority = item.get("priority", "Desconocido")
                start_time = item.get("start_time", "Desconocido")
                agent_id = item.get("agent_id", "Desconocido")
                resul_text.insert(tk.END, f"\n\nName: {name}\nPriority: {priority}\nStart Time: {start_time}\nID agente: {agent_id}\n")
        else: 
            resul_text.insert(tk.END, f"\n\nNo se encontraron procesos para el agente {agent}\n\n")



 nueva_ventana = tk.Tk()
 nueva_ventana.title("Opciones avanzadas")
 nueva_ventana.geometry("600x600")
 # Crea el frame principal
 frame_principal = tk.Frame(nueva_ventana)
 frame_principal.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
 # Crea los frames para cada elemento
 frame_resul = tk.Frame(frame_principal)
 frame_resul.pack(side=tk.TOP, fill=tk.BOTH, padx=10, pady=10, expand=True)
 frame_botones = tk.Frame(frame_principal)
 frame_botones.pack(side=tk.TOP, fill=tk.BOTH, padx=10, pady=10, expand=True)
 frame_botones2 = tk.Frame(frame_principal)
 frame_botones2.pack(side=tk.TOP, fill=tk.BOTH, padx=10, pady=10, expand=True)
 frame_botones3 = tk.Frame(frame_principal)
 frame_botones3.pack(side=tk.TOP, fill=tk.BOTH, padx=10, pady=10, expand=True)
 #Etiqueta para resultados
 lbl_resul = tk.Label(frame_resul, text="Resultados de consultas:")
 lbl_resul.pack(side=tk.TOP)
 #Crea el cuadro de resultados
 resul_text = tk.Text(frame_resul, height=10)
 resul_text.pack(side=tk.RIGHT, fill=tk.BOTH, padx=10, pady=10)
 # Botón de Estado
 btn_estado = tk.Button(frame_botones, text="Estado del servidor", command=consultar_estado)
 btn_estado.pack(side=tk.LEFT, padx=10, pady=10)
 # Botón de Configuración
 btn_config = tk.Button(frame_botones, text="Configuración del servidor", command=ver_configuracion)
 btn_config.pack(side=tk.LEFT, padx=10, pady=10)
 # Botón de Logs
 btn_logs = tk.Button(frame_botones, text="Consultar Logs", command=ver_logs)
 btn_logs.pack(side=tk.LEFT, padx=10, pady=10)
 # Botón de Logs resumen
 btn_resum = tk.Button(frame_botones, text="Ver resumen de logs", command=ver_resumen)
 btn_resum.pack(side=tk.LEFT, padx=10, pady=10)
 # Botón de traer grupos
 btn_traergrup = tk.Button(frame_botones2, text="Traer Grupos", command=traer_grupos)
 btn_traergrup.pack(side=tk.LEFT, padx=10, pady=10)
# Botón de estado de tareas
 btn_tareas = tk.Button(frame_botones2, text="Traer tareas", command=traer_tareas)
 btn_tareas.pack(side=tk.LEFT, padx=10, pady=10)
# Botón de Info de hardware
 btn_hw = tk.Button(frame_botones2, text="Información de hardware", command=info_hard)
 btn_hw.pack(side=tk.LEFT, padx=10, pady=10)
# Botón de Info de hotfixes
 btn_hotf = tk.Button(frame_botones2, text="Traer hotfixes", command=traer_hotfix)
 btn_hotf.pack(side=tk.LEFT, padx=10, pady=10)
# Botón de Info de ip
 btn_ip = tk.Button(frame_botones2, text="Consultar IP", command=traer_ip)
 btn_ip.pack(side=tk.LEFT, padx=10, pady=10)
# Botón de interfaz
 btn_inter = tk.Button(frame_botones3, text="Ver Interfaces", command=traer_interfaz)
 btn_inter.pack(side=tk.LEFT, padx=10, pady=10)
# Botón de routeo
 btn_rut = tk.Button(frame_botones3, text="Ver routing", command=traer_ruteo)
 btn_rut.pack(side=tk.LEFT, padx=10, pady=10)
 # Botón de sistema operativo
 btn_so = tk.Button(frame_botones3, text="Ver SO", command=traer_so)
 btn_so.pack(side=tk.LEFT, padx=10, pady=10)
 # Botón de paquetes
 btn_pack = tk.Button(frame_botones3, text="Ver paquetes", command=traer_pack)
 btn_pack.pack(side=tk.LEFT, padx=10, pady=10)
  # Botón de puertos
 btn_port = tk.Button(frame_botones3, text="Ver puertos", command=traer_puertos)
 btn_port.pack(side=tk.LEFT, padx=10, pady=10)
  # Botón de procesos
 btn_pross = tk.Button(frame_botones3, text="Ver procesos", command=traer_procesos)
 btn_pross.pack(side=tk.LEFT, padx=10, pady=10)

 nueva_ventana.mainloop()

# Crea las listas para los agentes y los grupos
lista_agentes = tk.Listbox(frame_agentes, selectmode="multiple", exportselection=False, listvariable=opciones_agentes, width=25)
lista_agentes.pack(side=tk.TOP)
lista_agentes.bind("<<ListboxSelect>>", actualizar_agente)
lista_grupos = tk.Listbox(frame_grupos, selectmode="single", exportselection=False, listvariable=opciones_grupos, width=20)
lista_grupos.pack(side=tk.TOP)
lista_grupos.bind("<<ListboxSelect>>", actualizar_grupo)
# Crea el menú de Severidad
menu_severidad = tk.OptionMenu(frame_severidad, severidad_seleccionado, *opciones_severidad)
menu_severidad.pack(side=tk.TOP, padx=10, pady=10)
menu_severidad.bind("<<MenuSelect>>", actualizar_severidad)

#Crea el menú de Vulnerabilidades
opciones_vulnerabilidades_str.set(",".join(opciones_vulnerabilidades)) # asignar el valor inicial de la lista de opciones a la variable StringVar
menu_vulnerabilidades = tk.OptionMenu(frame_vulnerabilidades, vulnerabilidad_seleccionada, opciones_vulnerabilidades_str)
menu_vulnerabilidades.pack(side=tk.TOP, padx=10, pady=10)
menu_vulnerabilidades.bind("<<MenuSelect>>", actualizar_vulnerabilidad)

#Crea el cuadro de resultados
resultados_text = tk.Text(frame_resultados, height=10)
resultados_text.pack(side=tk.TOP, fill=tk.BOTH, padx=10, pady=10)

#Crea cuadro de entrada y botón de enviar
etiqueta = tk.Label(frame_entrada, text="Ingrese la palabra clave para la búsqueda de vulnerabilidades:")
etiqueta.pack(side=tk.TOP)
entrada = tk.Entry(frame_entrada, font=("Arial", 12))
entrada.pack()
boton = tk.Button(frame_entrada, text="Buscar", command=buscar)
boton.pack(side=tk.TOP, padx=10, pady=10)

# Crea el botón de Conectar
btn_conectar = tk.Button(ventana, text="Conectar", command=conectarse)
btn_conectar.pack(side=tk.LEFT, padx=10, pady=10)

# Crea el botón de Consultar por severidad
btn_consultarseveridad = tk.Button(frame_severidad, text="Consultar", command=consultar_severidad)
btn_consultarseveridad.pack(side=tk.TOP, padx=10, pady=10)

# Crea el botón de Consultar por CVE
btn_consultarcve = tk.Button(frame_vulnerabilidades, text="Consultar", command=consultar_cve)
btn_consultarcve.pack(side=tk.TOP, padx=10, pady=10)

# Crea el botón de Consultar agente
btn_consultaragente = tk.Button(frame_agentes, text="Consultar", command=consultar_agente)
btn_consultaragente.pack(side=tk.TOP, padx=10, pady=10)

# Crea el botón de Consultar grupo
btn_consultarGrupo = tk.Button(frame_grupos, text="Consultar", command=consultar_grupos)
btn_consultarGrupo.pack(side=tk.TOP, padx=10, pady=10)

# Crea el botón de Tops
#Etiqueta para Tops
lbl_vulnerabilidades = tk.Label(frame_vulnerabilidades, text="Selecciones para ver")
lbl_vulnerabilidades.pack(side=tk.BOTTOM)
btn_consultartop10vul = tk.Button(frame_vulnerabilidades, text="Top 10 vulnerabilidades", command=mostrar_top_vul)
btn_consultartop10vul.pack(side=tk.BOTTOM, padx=10, pady=10)
btn_consultartop10ag = tk.Button(frame_vulnerabilidades, text="Top 10 Agentes", command=mostrar_top_ag)
btn_consultartop10ag.pack(side=tk.BOTTOM, padx=10, pady=10)

# Crea el botón de Funciones extra
#Etiqueta para extras
lbl_vulnerabilidades = tk.Label(frame_severidad, text="Oprima para ver las opciones avanzadas")
lbl_vulnerabilidades.pack(side=tk.BOTTOM)
btn_consultarExtras = tk.Button(frame_severidad, text="Opciones Avanzadas", command=ir_extras)
btn_consultarExtras.pack(side=tk.BOTTOM, padx=10, pady=10)

def actualizar(*args):
    global protocol
    global host 
    global port
    global requests_headers
    #Define the name of the agent you want to upgrade
    agente = agente_seleccionado.get()
    resultados_text.delete("1.0", tk.END)
    print(agente)
    if agente:
        # Define your Wazuh API endpoint and authentication headers
        endpoint = f'{protocol}://{host}:{port}'
        # Search for the agent ID based on the agent name
        url_searchID = f'{endpoint}/agents?select=id&search={agente}'
        response = requests.get(url_searchID, headers=requests_headers, verify=False)
        print("Contenido de la respuesta :", response.content)
        resultados_text.delete("1.0", tk.END)

        if response.status_code == 200:
            # Parse the response JSON to extract the agent ID
            agent_id = json.loads(response.content.decode())['data']['affected_items'][0]['id']
            print(f'Found agent ID {agent_id} for agent {agente}')
            # Use the agent ID to upgrade the agent
            url = f'{endpoint}/agents/upgrade?agents_list={agent_id}&pretty=true'
            response = requests.put(url, headers=requests_headers, verify=False)
            print(response.content.decode())
            if response.status_code == 200:
                print(f'Successfully upgraded agent {agente}')
                resultados_text.insert(tk.END,"Agente actualizado con éxito\n")
            else:
                print(f'Error upgrading agent {agente}: {response.text}')
                resultados_text.insert(tk.END,"Hubo un error al intentar actualizar el agente\n")
        else:
            print(f'Error searching for agent {agente}: {response.text}')
            resultados_text.insert(tk.END,"Hubo un error al intentar actualizar el agente\n")
    else: 
        resultados_text.insert(tk.END,"Favor de seleccionar un agente\n")


def borrar(*args):
    global protocol
    global host 
    global port
    global requests_headers
    global opciones_agentes
    #Define the name of the agent you want to delete
    agente = agente_seleccionado.get()
    resultados_text.delete("1.0", tk.END)
    print(agente)
    if agente:
        # Define your Wazuh API endpoint and authentication headers
        endpoint = f'{protocol}://{host}:{port}'
        # Search for the agent ID based on the agent name
        url_searchID = f'{endpoint}/agents?select=id&search={agente}'
        response = requests.get(url_searchID, headers=requests_headers, verify=False)
        print("Contenido de la respuesta :", response.content)
        resultados_text.delete("1.0", tk.END)

        if response.status_code == 200:
            # Parse the response JSON to extract the agent ID
            agent_id = json.loads(response.content.decode())['data']['affected_items'][0]['id']
            print(f'Found agent ID {agent_id} for agent {agente}')
            # Use the agent ID to delete the agent
            url = f'{endpoint}/agents?pretty=true&older_than=0s&agents_list={agent_id}&status=all'
            response = requests.delete(url, headers=requests_headers, verify=False)
            print(response.content.decode())

            if response.status_code == 200:
                print(f'Successfully deleted agent {agente}')
                resultados_text.insert(tk.END,"Agente eliminado con éxito\n")

            else:
                print(f'Error deleting agent {agente}: {response.text}')
                resultados_text.insert(tk.END,"Hubo un error al intentar eliminar el agente\n")
        else:
            print(f'Error deleting {agente}: {response.text}')
            resultados_text.insert(tk.END,"Hubo un error al intentar eliminar el agente\n")

        url_agentesActualizados = f'{endpoint}/agents?pretty=true&sort=-ip,name'
        newOpciones =[]
        lactulizadaAgentes = requests.get(url_agentesActualizados, headers=requests_headers, verify=False)
        resp = json.loads(lactulizadaAgentes.content.decode())['data']['affected_items'] #Así se convierte y maneja como un objeto por bloques 
        for i in resp:
            nombre = i['name'] # Obtener el nombre del elemento actual
            newOpciones.append(nombre)
            opciones_agentes.set(newOpciones) # Asignar la cadena al objeto opciones_agentes para actualizar la vista
    else: 
        resultados_text.insert(tk.END,"Favor de seleccionar un agente\n")


def reiniciar(*args):
    global protocol
    global host 
    global port
    global requests_headers
    global opciones_agentes
    #Define the name of the agent you want to restart
    agente = agente_seleccionado.get()
    resultados_text.delete("1.0", tk.END)
    print(agente)
    if agente: 
        # Define your Wazuh API endpoint and authentication headers
        endpoint = f'{protocol}://{host}:{port}'
        # Search for the agent ID based on the agent name
        url_searchID = f'{endpoint}/agents?select=id&search={agente}'
        response = requests.get(url_searchID, headers=requests_headers, verify=False)
        print("Contenido de la respuesta :", response.content)
        resultados_text.delete("1.0", tk.END)

        if response.status_code == 200:
            # Parse the response JSON to extract the agent ID
            agent_id = json.loads(response.content.decode())['data']['affected_items'][0]['id']
            print(f'Found agent ID {agent_id} for agent {agente}')

            # Use the agent ID to delete the agent
            url = f'{endpoint}/agents/restart?pretty=true&agents_list={agent_id}'
            response = requests.put(url, headers=requests_headers, verify=False)
            print(response.content.decode())

            if response.status_code == 200:
                print(f'Successfully restarted agent {agente}')
                resultados_text.insert(tk.END,"Agente reiniciado con éxito.\n")

            else:
                print(f'Error restarting agent {agente}: {response.text}')
                resultados_text.insert(tk.END,"Hubo un error al intentar reiniciar el agente\n")
        else:
            print(f'Error restartin agent {agente}: {response.text}')
            resultados_text.insert(tk.END,"Hubo un error al intentar reiniciar el agente\n")
    else: 
        resultados_text.insert(tk.END,"Favor de seleccionar un agente\n")

def añadir(*args):
    global protocol
    global host 
    global port
    global requests_headers
    global opciones_agentes
    name = name_entry.get()
    agent_id = id_entry.get()
    ip_address = ip_entry.get()
    resultados_text.delete("1.0", tk.END)
    if name and agent_id and ip_address:
        data = {
            "name": name,
            "id": agent_id,
            "ip": ip_address,
        }
        print(type(data))
        # Define your Wazuh API endpoint and authentication headers
        endpoint = f'{protocol}://{host}:{port}'
        url = f'{endpoint}/agents/insert'
        response = requests.post(url,json=data, headers=requests_headers, verify=False)
        print(response)
        print(response.content.decode())
        resultados_text.delete("1.0", tk.END)

        if response.status_code == 200:
            print(f'Agent{name} added succesfully')
            resultados_text.insert(tk.END,"Agente añadido con éxito\n")
        else:
            print(f'Error added agent {name}: {response.text}')
            resultados_text.insert(tk.END,"Hubo un error al intentar añadir el agente\n")
    else: 
        resultados_text.insert(tk.END,"Favor de ingresar los datos\n")

# Crea el botón de actualizar
btn_actualizar = tk.Button(ventana, text="Actualizar agentes seleccionados", command=actualizar)
btn_actualizar.pack(side=tk.LEFT, padx=10, pady=10)

#Crea el botón de borrar
btn_reiniciar = tk.Button(ventana, text="Reiniciar agentes seleccionados", command=reiniciar)
btn_reiniciar.pack(side=tk.LEFT, padx=10, pady=10)

#Crea el botón de reiniciar
btn_actualizar = tk.Button(ventana, text="Borrar agentes seleccionados", command=borrar)
btn_actualizar.pack(side=tk.LEFT, padx=10, pady=10)

#Crea el botón de añadir
btn_actualizar = tk.Button(ventana, text="Añadir agente", command=añadir)
btn_actualizar.pack(side=tk.LEFT, padx=10, pady=10)

#Loop principal para la visualización
ventana.mainloop()
