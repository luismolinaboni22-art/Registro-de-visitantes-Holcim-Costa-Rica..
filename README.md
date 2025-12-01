# Registro de Visitantes - Holcim Costa Rica

Proyecto Flask para registro de visitantes con identidad visual Holcim.

Instrucciones rápidas:

1. Copia `.env.example` a `.env` y ajusta SECRET_KEY si quieres.
2. Crear entorno virtual e instalar dependencias:
   ```
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
3. Inicializar base de datos y crear sitios por defecto:
   ```
   flask init-db
   flask create-default-sites
   flask create-admin
   ```
4. Ejecutar local:
   ```
   flask run
   ```

Deploy recomendado: Render (use Procfile).
