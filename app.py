import os
import requests
import pandas as pd
from urllib.parse import urlencode
from flask import Flask, redirect, request, session, render_template
import base64
from datetime import datetime
import time

SLEEP = 0.2  # para evitar throttling simples

def b64(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode("utf-8")).decode("utf-8").rstrip("=")

def iso_parse(s):
    try:
        return datetime.fromisoformat(s.replace("Z","+00:00"))
    except Exception:
        return None

def safe_get(d, path, default=None):
    cur = d
    for p in path.split("."):
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur

def dm_list_hubs(token):
    url = "https://developer.api.autodesk.com/project/v1/hubs"
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"})
    r.raise_for_status()
    return r.json().get("data", [])

def dm_list_projects(token, hub_id):
    url = f"https://developer.api.autodesk.com/project/v1/hubs/{hub_id}/projects"
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"})
    r.raise_for_status()
    return r.json().get("data", [])

def dm_top_folders(token, hub_id, project_id):
    url = f"https://developer.api.autodesk.com/project/v1/hubs/{hub_id}/projects/{project_id}/topFolders"
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"})
    r.raise_for_status()
    return r.json().get("data", [])

def dm_folder_contents(token, project_id, folder_id):
    url = f"https://developer.api.autodesk.com/data/v1/projects/{project_id}/folders/{folder_id}/contents"
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"})
    r.raise_for_status()
    return r.json().get("data", [])

def dm_item_versions(token, project_id, item_id):
    url = f"https://developer.api.autodesk.com/data/v1/projects/{project_id}/items/{item_id}/versions"
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"})
    r.raise_for_status()
    return r.json().get("data", [])

def acc_list_project_users(token, account_id, project_id):
    url = f"https://api.acc.autodesk.com/project/v1/accounts/{account_id}/projects/{project_id}/users"
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"})
    if r.status_code != 200:
        print(f"⚠️ Não foi possível listar usuários do projeto {project_id} (HTTP {r.status_code}): {r.text[:200]}")
        return []
    return r.json().get("results", []) or r.json().get("users", [])

def md_metadata(token, urn_b64):
    url = f"https://developer.api.autodesk.com/modelderivative/v2/designdata/{urn_b64}/metadata"
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"})
    if r.status_code != 200:
        return None
    return r.json()

def md_properties(token, urn_b64, guid):
    url = f"https://developer.api.autodesk.com/modelderivative/v2/designdata/{urn_b64}/metadata/{guid}/properties"
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"})
    if r.status_code != 200:
        return None
    return r.json()

def scan_project(token, hub, project):
    hub_id = hub["id"]
    project_id = project["id"]
    project_name = project["attributes"]["name"]
    top = dm_top_folders(token, hub_id, project_id)
    containers_iso = {"WIP":0, "Shared":0, "Published":0, "Archive":0}
    files_rows, versions_rows, per_file_versions = [], [], []

    for f in top:
        if f["type"] != "folders": continue
        stack = [f]
        while stack:
            node = stack.pop()
            time.sleep(SLEEP)
            contents = dm_folder_contents(token, project_id, node["id"])
            for c in contents:
                if c["type"] == "folders":
                    stack.append(c)
                elif c["type"] == "items":
                    item_id = c["id"]
                    name = c["attributes"]["displayName"]
                    top_name = f["attributes"]["name"]
                    if top_name in containers_iso:
                        containers_iso[top_name] += 1

                    time.sleep(SLEEP)
                    versions = dm_item_versions(token, project_id, item_id)
                    vcount = len(versions)
                    per_file_versions.append({
                        "hub_id": hub_id, "project_id": project_id, "project_name": project_name,
                        "item_id": item_id, "file_name": name, "versions": vcount
                    })

                    timestamps = []
                    for v in versions:
                        created = safe_get(v, "attributes.createTime") or safe_get(v, "attributes.lastModifiedTime")
                        timestamps.append((v["id"], created, safe_get(v, "relationships.derivatives.data.id") or v.get("id")))
                        files_rows.append({
                            "hub_id": hub_id, "project_id": project_id, "project_name": project_name,
                            "item_id": item_id, "file_name": name, "version_id": v["id"], "created_at": created,
                            "derivative_urn": timestamps[-1][2]
                        })

                    if len(timestamps) >= 2:
                        ts_sorted = sorted([iso_parse(t[1]) for t in timestamps if t[1]], key=lambda x: x)
                        gaps = [(ts_sorted[i] - ts_sorted[i-1]).total_seconds()/3600.0 for i in range(1, len(ts_sorted))]
                        avg_gap_h = sum(gaps)/len(gaps) if gaps else None
                    else:
                        avg_gap_h = None

                    versions_rows.append({
                        "hub_id": hub_id, "project_id": project_id, "project_name": project_name,
                        "item_id": item_id, "file_name": name, "versions": vcount,
                        "avg_gap_hours": round(avg_gap_h,2) if avg_gap_h else None
                    })

    df_files = pd.DataFrame(files_rows)
    df_perfile = pd.DataFrame(per_file_versions)
    df_top10 = df_perfile.sort_values("versions", ascending=False).head(10)
    df_versions = pd.DataFrame(versions_rows)
    
    account_id = hub_id.split(".")[-1] if "." in hub_id else None
    users_count = None
    if account_id:
        users = acc_list_project_users(token, account_id, project_id)
        users_count = len(users) if users else None

    project_summary = {
        "hub_id": hub_id, "project_id": project_id, "project_name": project_name,
        "total_files": len(df_perfile), "total_versions": int(df_perfile["versions"].sum()) if not df_perfile.empty else 0,
        "users_count": users_count, "wip_files": containers_iso["WIP"], "shared_files": containers_iso["Shared"],
        "published_files": containers_iso["Published"], "archive_files": containers_iso["Archive"]
    }
    return project_summary, df_files, df_perfile, df_top10, df_versions

def extract_model_properties_sample(token, df_files, project_name, project_id, max_models=3):
    candidates = df_files[df_files["file_name"].str.lower().str.endswith((".rvt",".ifc",".nwd",".nwc",".dwg",".dgn"), na=False)]
    if candidates.empty: return pd.DataFrame(), pd.DataFrame()

    latest_by_item = candidates.sort_values("created_at").groupby("item_id").tail(1)
    sample = latest_by_item.tail(max_models)
    props_rows, class_audit_rows = [], []

    for _, row in sample.iterrows():
        urn = row.get("derivative_urn") or row.get("version_id")
        if not urn: continue
        urn_b64 = b64(urn)
        meta = md_metadata(token, urn_b64)
        guid = safe_get(meta, "data.metadata.0.guid")
        if not guid: continue
        props = md_properties(token, urn_b64, guid)
        if not props: continue
        
        objects = safe_get(props, "data.collection") or safe_get(props, "data.objects") or []
        for obj in objects:
            pmap = {}
            for grp_name, grp_vals in obj.get("properties", {}).items():
                for k, v in grp_vals.items(): pmap[f"{grp_name}.{k}"] = v
            
            cat = pmap.get("Item.Category") or pmap.get("Identity Data.Category") or pmap.get("Constraints.Category")
            cls = pmap.get("Identity Data.Uniclass") or pmap.get("Identity Data.OmniClass Number")
            has_class = cls is not None and str(cls).strip() != ""
            
            props_rows.append({
                "project_id": project_id, "project_name": project_name, "item_id": row["item_id"],
                "file_name": row["file_name"], "category": cat, "has_classification": has_class, "classification_value": cls
            })
    
    return pd.DataFrame(props_rows), pd.DataFrame(class_audit_rows)

# =========================================================
# 🔑 CREDENCIAIS E CONFIGURAÇÃO
# =========================================================
CLIENT_ID = os.environ.get("CLIENT_ID") # Melhor usar variáveis de ambiente!
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
#REDIRECT_URI = "https://quanta-dashboard.onrender.com/callback" # A URL da sua aplicação!
SCOPES = "data:read account:read"
REDIRECT_URI = 'http://127.0.0.1:8080/callback'

app = Flask(__name__)
# A secret_key é essencial para gerenciar as sessões de login de forma segura
app.secret_key = os.environ.get("FLASK_SECRET_KEY")


# =========================================================
# (COLE AQUI O BLOCO COMPLETO DE FUNÇÕES DA AUTODESK)
# ... def dm_list_hubs(token): ...
# ... def scan_project(token, hub, project): ...
# =========================================================
# (Para o exemplo funcionar, vou adicionar apenas a dm_list_hubs)
def dm_list_hubs(token):
    url = "https://developer.api.autodesk.com/project/v1/hubs"
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"})
    r.raise_for_status()
    return r.json().get("data", [])


def oauth_get_access_token(auth_code):
    url = "https://developer.api.autodesk.com/authentication/v2/token"
    payload = {
        "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
        "grant_type": "authorization_code", "code": auth_code,
        "redirect_uri": REDIRECT_URI
    }
    r = requests.post(url, data=payload)
    r.raise_for_status()
    return r.json()["access_token"]


# =========================================================
# 🖥️ ROTAS DA APLICAÇÃO
# =========================================================

@app.route('/')
def home():
    # Verifica se o token já existe na sessão do usuário
    if 'autodesk_token' in session:
        # Se sim, manda direto para o dashboard
        return redirect('/dashboard')
    # Se não, mostra a página de login
    return render_template('login.html')

@app.route('/login')
def login():
    # Inicia o processo de autenticação redirecionando para a Autodesk
    params = {"response_type": "code", "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI, "scope": SCOPES}
    auth_url = f"https://developer.api.autodesk.com/authentication/v2/authorize?{urlencode(params)}"
    return redirect(auth_url)

@app.route('/callback')
def callback():
    # Rota que a Autodesk chama DEPOIS que o usuário autoriza
    try:
        auth_code = request.args.get('code')
        access_token = oauth_get_access_token(auth_code)
        
        # Guarda o token de forma segura na sessão do usuário
        session['autodesk_token'] = access_token
        
        # Redireciona para a página principal do dashboard
        return redirect('/dashboard')
    except Exception as e:
        return f"Ocorreu uma falha na autenticação: {e}", 500

@app.route('/dashboard')
def dashboard():
    # Protege a página: só acessa quem tem token na sessão
    if 'autodesk_token' not in session:
        return redirect('/')

    try:
        access_token = session['autodesk_token']
        # Usa o token para buscar os dados da Autodesk
        hubs = dm_list_hubs(access_token)
        
        # Passa os dados para o template HTML para serem exibidos
        return render_template('dashboard.html', hubs=hubs)
    except Exception as e:
        return f"Erro ao buscar dados da Autodesk: {e}", 500

@app.route('/logout')
def logout():
    # Limpa a sessão do usuário
    session.pop('autodesk_token', None)
    return redirect('/')

if __name__ == "__main__":
    # Roda o servidor de desenvolvimento. Em produção, usamos Gunicorn.
    app.run(host='0.0.0.0', port=8080, debug=True)