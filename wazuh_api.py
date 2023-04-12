import tkinter as tk
import json
import requests
import urllib3
from base64 import b64encode
ventana = tk.Tk()
# Define el título de la ventana
ventana.title("Consulta Wazuh")
# Define las dimensiones de la ventana
ventana.geometry("900x300")
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
frame_resultados.pack(side=tk.BOTTOM, fill=tk.BOTH, padx=10, pady=10, expand=True)
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

# Define las opciones de los agentes ,los grupos y vulnerabilidades
opciones_agentes = tk.StringVar(value=[])
opciones_grupos = tk.StringVar(value=[])
opciones_vulnerabilidades = ["CVE-2021-1234", "CVE-2021-5678", "CVE-2021-9012", "CVE-2021-3456", "CVE-2021-7890"]
# Define las opciones del menú de Severidad
opciones_severidad = ["Todas", "Críticas", "Altas", "Medias", "Bajas"]

# Variables para almacenar las selecciones de las listas
agente_seleccionado = tk.StringVar()
grupo_seleccionado = tk.StringVar()
severidad_seleccionado = tk.StringVar()
vulnerabilidad_seleccionada = tk.StringVar()

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
def obtener_selecciones():
    agente = agente_seleccionado.get()
    grupo = grupo_seleccionado.get()
    severidad = severidad_seleccionado.get()
    vulnerabilidad = vulnerabilidad_seleccionada.get()
    resultados_text.delete("1.0", tk.END)
    resultados_text.insert(tk.END, "Agente seleccionado: " + agente + "\n")
    resultados_text.insert(tk.END, "Grupo seleccionado: " + grupo + "\n")
    resultados_text.insert(tk.END, "Severidad seleccionada: " + severidad + "\n")
    resultados_text.insert(tk.END, "Vulnerabilidad seleccionada: " + vulnerabilidad + "\n")

    print("Agente seleccionado:", agente)
    print("Grupo seleccionado:", grupo)
    print("Severidad seleccionada:", severidad)
    print("Vulnerabilidad seleccionada:", vulnerabilidad)

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

    response = requests.get(f"{protocol}://{host}:{port}/agents?pretty=true", headers=requests_headers, verify=False) # Solicitud de los agentes
    print(response.text) #Imprime el Json
    resp = json.loads(response.content.decode())['data']['affected_items'] #Así se convierte y maneja como un objeto por bloques 

    for i in resp:
        nombre = i['name'] # Obtener el nombre del elemento actual
        id = i['id'] # Obtener el ide del elemento actual
        aux = nombre + " " + id
        opciones.append(aux)

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
    return grupos


# Crea las listas para los agentes y los grupos
lista_agentes = tk.Listbox(frame_agentes, selectmode="single", exportselection=False, listvariable=opciones_agentes, width=20)
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
menu_vulnerabilidades = tk.OptionMenu(frame_vulnerabilidades, vulnerabilidad_seleccionada, *opciones_vulnerabilidades)
menu_vulnerabilidades.pack(side=tk.TOP, padx=10, pady=10)
menu_vulnerabilidades.bind("<<MenuSelect>>", actualizar_vulnerabilidad)

#Crea el cuadro de resultados
resultados_text = tk.Text(frame_resultados, height=10)
resultados_text.pack(side=tk.TOP, fill=tk.BOTH, padx=10, pady=10)

# Crea el botón de Conectar
btn_consultar = tk.Button(ventana, text="Conectar", command=conectarse)
btn_consultar.pack(side=tk.LEFT, padx=10, pady=10)

# Crea el botón de Consultar
btn_consultar = tk.Button(ventana, text="Consultar", command=obtener_selecciones)
btn_consultar.pack(side=tk.LEFT, padx=10, pady=10)

#Loop principal para la visualización
ventana.mainloop()
