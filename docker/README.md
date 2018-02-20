docker for test Sysrepo plugin.

## build dockerfile

```
$ docker build -t sysrepo/sysrepo-netopeer2:test_plugin -f Dockerfile .
```

## run dockerfile with supervisor

```
$ docker run -i -t -v /opt/yang:/opt/fork --name test_plugin --rm sysrepo/sysrepo-netopeer2:test_plugin
```

## run dockerfile without supervisor

```
$ docker run -i -t -v /opt/yang:/opt/fork --name test_plugin --rm sysrepo/sysrepo-netopeer2:test_plugin bash
$ ubusd &
$ rpcd &
$ sysrepod
$ sysrepo-plugind
$ netopeer2-server
```
