# Configuring

## Enabling

``` {.lua}
Component "rooms.example.net" "muc"
modules_enabled = {
    "muc_room_mention_notifications";
}
```

## Settings

|Name |Description |Default |
|-----|------------|--------|
|muc_rmn_notify_unaffiliated_users| Notify mentioned users even if they are not members of the room they were mentioned in | false |
