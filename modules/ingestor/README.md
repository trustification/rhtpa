# Ingestor

## Upload an SBOM

```shell
cat file.sbom | http POST localhost:8080/api/v1/sbom location==cli
```

## Upload a dataset

```shell
http POST localhost:8080/api/v1/dataset @file-to-upload
```
