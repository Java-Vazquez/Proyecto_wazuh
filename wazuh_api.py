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
frame_entries = tk.Frame(frame_agentes)
frame_entries.pack(side=tk.BOTTOM, pady=10)
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
#Etiqueta para los campos del agente que se desea añadir
name_label = tk.Label(frame_entries, text="Name:")
name_label.grid(row=0, column=0)
name_entry = tk.Entry(frame_entries)
name_entry.grid(row=0, column=1)

id_label = tk.Label(frame_entries, text="ID:")
id_label.grid(row=1, column=0)
id_entry = tk.Entry(frame_entries)
id_entry.grid(row=1, column=1)

ip_label = tk.Label(frame_entries, text="IP Address:")
ip_label.grid(row=2, column=0)
ip_entry = tk.Entry(frame_entries)
ip_entry.grid(row=2, column=1)

#Etiqueta para resultados
lbl_vulnerabilidades = tk.Label(frame_resultados, text="Resultados de consultas:")
lbl_vulnerabilidades.pack(side=tk.TOP)

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
    common_vul = requests.get(f"{protocol}://{host}:{port}/vulnerability/001?q=cve={vulnerabilidad}&limit=800&pretty=true", headers=requests_headers, verify=False)
    #print(common_vul.text)
    data = json.loads(common_vul.text)
    # Extrae los elementos que necesitas del diccionario
    name = data['data']['affected_items'][0]['name']
    updated = data['data']['affected_items'][0]['updated']
    version = data['data']['affected_items'][0]['version']
    status = data['data']['affected_items'][0]['status']
    severity = data['data']['affected_items'][0]['severity']
    resultados_text.insert(tk.END,vulnerabilidad + "\n" + "Nombre: " + name + "\n" + "Actualización: "+ updated + "\n" + "Versión: " + version + "\n"+ "Estado: " + status + "\n" + "Severidad: "+ severity + "\n")
    print("Severidad seleccionada:", vulnerabilidad)

def consultar_agente (*args):
    global protocol
    global host 
    global port
    global requests_headers
    agente = agente_seleccionado.get()
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

def consultar_grupos(*args):
    global protocol
    global host 
    global port
    global requests_headers
    grupo = grupo_seleccionado.get()
    resultados_text.delete("1.0", tk.END)
    solicitud = requests.get(f"{protocol}://{host}:{port}/groups?search={grupo}&pretty=true", headers=requests_headers, verify=False)
    data =json.loads(solicitud.text)
    if data['data']['affected_items']:
        count = data['data']['affected_items'][0]['count']
        resultados_text.insert(tk.END,grupo + "\n" + "Número de agentes: " + str(count) + "\n")
    else:
        resultados_text.insert(tk.END, "No se encontraron agentes el el grupo.\n")


def buscar(*args):
    #2. BUSQUEDA POR PALABRA CLAVE
    
    return

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
    protocol = 'https'
    host = '192.168.198.131'
    port = 55000
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
    opciones = []
    #Solicitud y proceso para obtener y mostrar los agentes y grupos
    response = requests.get(f"{protocol}://{host}:{port}/agents?pretty=true", headers=requests_headers, verify=False) # Solicitud de los agentes
    #print(response.text) #Imprime el Json
    resp = json.loads(response.content.decode())['data']['affected_items'] #Así se convierte y maneja como un objeto por bloques 

    for i in resp:
        nombre = i['name'] # Obtener el nombre del elemento actual
        opciones.append(nombre)

    data = json.loads(response.text)
    grupos = []
    for item in data['data']['affected_items']: #Así se convierte y maneja como un objeto por bloques 
        if 'group' in item: # Verifica si el grupo ya está en la lista 
            grupos += item['group'] 

    opciones_agentes.set(opciones) # Asignar la cadena al objeto opciones_agentes para actualizar la vista
    grupos_str = ", ".join(list(set(grupos))) # Convertir la lista de grupos en una cadena separada por comas
    opciones_grupos.set(grupos_str) # Asignar la cadena al objeto opciones_grupos para actualizar la vista
    print(opciones_agentes.get()) # Imprimir la lista completa de nombres
    print(list(set(grupos)))

    # Solicitud para las severidades existentes
    response2 = requests.get(f"{protocol}://{host}:{port}/vulnerability/001?q=severity=Critical,severity=High,severity=Medium,severity=Low&pretty=true", headers=requests_headers, verify=False)
    data2 = json.loads(response2.text)
    vulnerabilidades = []
    for vul in data2['data']['affected_items']:
        if 'cve' in vul:
            cves = vul['cve']
        if isinstance(cves, list):
            vulnerabilidades += cves
        else:
            vulnerabilidades.append(cves)
    opciones_vulnerabilidades = vulnerabilidades
    opciones_vulnerabilidades_str.set(" ".join(opciones_vulnerabilidades)) # actualizar el valor de la variable StringVar con la nueva lista de opciones
    
    menu_vulnerabilidades['menu'].delete(0, 'end')
    for vulnerabilidad in opciones_vulnerabilidades:
        menu_vulnerabilidades['menu'].add_command(label=vulnerabilidad, command=lambda v=vulnerabilidad: vulnerabilidad_seleccionada.set(v))
    print(opciones_vulnerabilidades) # Imprimir la lista completa de nombres



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
        resul_text.insert(tk.END,"........................................................" + "\n")
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
 #Etiqueta para resultados
 lbl_resul = tk.Label(frame_resul, text="Resultados de consultas:")
 lbl_resul.pack(side=tk.TOP)
 #Crea el cuadro de resultados
 resul_text = tk.Text(frame_resul, height=10)
 resul_text.pack(side=tk.RIGHT, fill=tk.Y, padx=10, pady=10)
 # Botón de Estado
 btn_estado = tk.Button(frame_botones, text="Estado del servidor", command=consultar_estado)
 btn_estado.pack(side=tk.LEFT, padx=10, pady=10)
 # Botón de Configuración
 btn_config = tk.Button(frame_botones, text="Configuración del servidor", command=ver_configuracion)
 btn_config.pack(side=tk.LEFT, padx=10, pady=10)
 # Botón de Logs
 btn_config = tk.Button(frame_botones, text="Consultar Logs", command=ver_logs)
 btn_config.pack(side=tk.LEFT, padx=10, pady=10)
 # Botón de Logs resumen
 btn_config = tk.Button(frame_botones, text="Ver resumen de logs", command=ver_resumen)
 btn_config.pack(side=tk.LEFT, padx=10, pady=10)
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

# Crea el botón de Funciones extra
#Etiqueta para extras
lbl_vulnerabilidades = tk.Label(frame_severidad, text="Oprima para ver las opciones avanzadas:")
lbl_vulnerabilidades.pack(side=tk.BOTTOM)
btn_consultarExtras = tk.Button(frame_severidad, text="Ir", command=ir_extras)
btn_consultarExtras.pack(side=tk.BOTTOM, padx=10, pady=10)


def actualizar(*args):
    global protocol
    global host 
    global port
    global requests_headers
    #global user 
    #global password
    #Define the name of the agent you want to upgrade
    agente = agente_seleccionado.get()
    print(agente)
    # Define your Wazuh API endpoint and authentication headers
    endpoint = f'{protocol}://{host}:{port}'

    # Search for the agent ID based on the agent name
    url_searchID = f'{endpoint}/agents?select=id&search={agente}'
    response = requests.get(url_searchID, headers=requests_headers, verify=False)
    print("Contenido de la respuesta :", response.content)

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
        else:
            print(f'Error upgrading agent {agente}: {response.text}')
    else:
        print(f'Error searching for agent {agente}: {response.text}')


def borrar(*args):
    global protocol
    global host 
    global port
    global requests_headers
    global opciones_agentes
    #Define the name of the agent you want to delete
    agente = agente_seleccionado.get()
    print(agente)
    # Define your Wazuh API endpoint and authentication headers
    endpoint = f'{protocol}://{host}:{port}'

    # Search for the agent ID based on the agent name
    url_searchID = f'{endpoint}/agents?select=id&search={agente}'
    response = requests.get(url_searchID, headers=requests_headers, verify=False)
    print("Contenido de la respuesta :", response.content)

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

        else:
            print(f'Error deleting agent {agente}: {response.text}')
    else:
        print(f'Error deleting {agente}: {response.text}')

    url_agentesActualizados = f'{endpoint}/agents?pretty=true&sort=-ip,name'
    newOpciones =[]
    lactulizadaAgentes = requests.get(url_agentesActualizados, headers=requests_headers, verify=False)
    resp = json.loads(lactulizadaAgentes.content.decode())['data']['affected_items'] #Así se convierte y maneja como un objeto por bloques 

    for i in resp:
        nombre = i['name'] # Obtener el nombre del elemento actual
        newOpciones.append(nombre)
        opciones_agentes.set(newOpciones) # Asignar la cadena al objeto opciones_agentes para actualizar la vista


def reiniciar(*args):
    global protocol
    global host 
    global port
    global requests_headers
    global opciones_agentes
    #Define the name of the agent you want to restart
    agente = agente_seleccionado.get()
    print(agente)
    # Define your Wazuh API endpoint and authentication headers
    endpoint = f'{protocol}://{host}:{port}'

    # Search for the agent ID based on the agent name
    url_searchID = f'{endpoint}/agents?select=id&search={agente}'
    response = requests.get(url_searchID, headers=requests_headers, verify=False)
    print("Contenido de la respuesta :", response.content)

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

        else:
            print(f'Error restarting agent {agente}: {response.text}')
    else:
        print(f'Error restartin agent {agente}: {response.text}')

def añadir(*args):
    global protocol
    global host 
    global port
    global requests_headers
    global opciones_agentes
    name = name_entry.get()
    agent_id = id_entry.get()
    ip_address = ip_entry.get()
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

    if response.status_code == 200:
        print(f'Agent{name} added succesfully')
    else:
        print(f'Error added agent {name}: {response.text}')
  

# Crea el botón de actualizar
btn_actualizar = tk.Button(ventana, text="Upgrade Selected Agents", command=actualizar)
btn_actualizar.pack(side=tk.LEFT, padx=10, pady=10)

#Crea el botón de borrar
btn_reiniciar = tk.Button(ventana, text="Restart Selected Agents", command=reiniciar)
btn_reiniciar.pack(side=tk.LEFT, padx=10, pady=10)

#Crea el botón de reiniciar
btn_actualizar = tk.Button(ventana, text="Delete Selected Agents", command=borrar)
btn_actualizar.pack(side=tk.LEFT, padx=10, pady=10)

#Crea el botón de añadir
btn_actualizar = tk.Button(ventana, text="Add Agent", command=añadir)
btn_actualizar.pack(side=tk.LEFT, padx=10, pady=10)

#Loop principal para la visualización
ventana.mainloop()
