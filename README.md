# calvopro-botv2-worker

## Heroku

* Clona este repositorio, lamentablemente Heroku no funciona como Python anywhere

```bash
git clone https://github.com/Gealber/calvopro-botv2-worker.git
cd calvopro-botv2-worker
```

* Create heroku app 
```bash
heroku create
```

* En caso de tener ubuntu o cualquier otra distribucion de linux, simplemente correr
```bash
bash env.sh
```

Esto va a declarar las necesarias variables de entorno en heroku.

En caso de no estar en una distribución de Linux, tendría que ponerlas manual, ya que no tengo idea de bat o powershell.
Para poner dichas variables manualmente sería:
```cmd
heroku config:set REDIS_URL=<url>
```
Dónde en <url> va el valor de esa variable de entorno en específico.

Se puede comprobar si se pusieron dichas variables de entorno de la siguiente manera:

```bash
heroku config
```

* Añadir los buildpacks necesarios:
```bash
heroku buildpacks:add heroku-community/apt 
heroku buildpacks:add https://github.com/heroku/heroku-buildpack-c.git
```

Comprobar si se añadieron:

```bash
heroku buildpacks
```

* Pushear para Heroku
```bash
git push heroku main
```

* Levantar el dyno con el worker
```bash
heroku ps:scale worker=1
```

* Comprobar que todo está ok
```bash
heroku logs -t
```

No tan sencillo como pensaba.
