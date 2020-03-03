---
title: "Building"
date: 2018-05-02T00:00:00+00:00
weight: 30
geekdocRepo: https://github.com/owncloud/ocis-phoenix
geekdocEditPath: edit/master/docs
geekdocFilePath: building.md
---

As this project is built with Go, so you need to install that first. The installation of Go is out of the scope of this document, please follow the official documentation for [Go](https://golang.org/doc/install), to build this project you have to install Go >= v1.12. After the installation of the required tools you need to get the sources:

{{< highlight txt >}}
git clone https://github.com/owncloud/ocis-phoenix.git
cd ocis-phoenix
{{< / highlight >}}

All required tool besides Go itself and make are bundled or getting automatically installed within the `GOPATH`. All commands to build this project are part of our `Makefile`.

## Backend

{{< highlight txt >}}
make generate
make build
{{< / highlight >}}

The above commands will download a [Phoenix](https://github.com/owncloud/phoenix) release and embed it into the binary. Finally you should have the binary within the `bin/` folder now, give it a try with `./bin/ocis-phoenix -h` to see all available options.
