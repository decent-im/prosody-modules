Prosody 0.12 added an API allowing modules to report their status. This
module allows reading these statuses via HTTP for use in monitoring.

```
$ curl http://prosody.localhost:5280/status
{
   "example.com" : {
      "c2s" : {
         "message" : "Loaded",
         "type" : "core"
      }
   }
}
```

