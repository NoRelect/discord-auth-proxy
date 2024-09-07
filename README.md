# discord-auth-proxy

## Locally building and running the docker image

If you want to locally build the docker image, you can run the following command:

```sh
docker build -t discord-auth-proxy:latest -f DiscordAuthProxy/Dockerfile .
```

To the run the image locally using your development settings, you can run:

```sh
docker run --rm -it -p 7160:8080 -v $(pwd)/DiscordAuthProxy/appsettings.Development.json:/app/appsettings.json:ro discord-auth-proxy:latest
```
