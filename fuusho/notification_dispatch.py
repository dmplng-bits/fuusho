"""
The single delivery choke point for outgoing notifications.

Anything that wants to notify a user calls dispatch_notification() here,
and it sends an E2E-encrypted APNs push to every registered device (each
paired via /api/pair/complete, each holding its own key).

Device failures are isolated: one stale device token never blocks the
others. Returns True if at least one device got the push.

The priority/tags parameters are accepted for caller convenience but
unused by APNs delivery today.
"""

from . import apns_client, state_store


def read_registered_devices():
    return state_store.read_state("devices")


def dispatch_notification(notification_title, notification_body, notification_priority="default", notification_tags=""):
    delivered_anywhere = False
    failures = []

    if apns_client.apns_is_configured():
        for device in read_registered_devices():
            try:
                apns_client.send_encrypted_notification(
                    device, notification_title, notification_body
                )
                delivered_anywhere = True
            except Exception as apns_error:
                failures.append(f"apns {device.get('name', device['token'][:8])}: {apns_error}")
    else:
        failures.append("apns: not configured — no delivery channel available")

    if failures:
        print(f"notification_dispatch: partial/failed delivery — {'; '.join(failures)}")
    return delivered_anywhere
