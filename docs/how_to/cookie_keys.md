# Rotate cookie encryption keys

Use this procedure to change session-cookie encryption keys while retaining
read access to existing cookies. It applies to both session drivers and, by
default, the engine's login-state cookies. Provider refresh-token rotation is a
separate task covered by the [rotation guide](crate::_docs::how_to::rotation).

## Build a sealer with one writer and multiple readers

Load the old and new keys from persistent secret storage. For native AES-GCM
key loading, see the [engine tutorial](crate::_docs::tutorial::getting_started).
The following helper accepts already-loaded AEAD keys. It seals with `active`
and can unseal with either key:

```rust
use std::sync::Arc;
use huskarl_login::{CookieSessionStore, InvalidCookieName};
use huskarl_login::core::crypto::{
    cipher::{AeadCipher, MultiKeyCipher, MultiKeyDecryptor},
    seal::AeadV1Sealer,
};

fn rotating_store(
    active: impl AeadCipher + 'static,
    other: impl AeadCipher + 'static,
) -> Result<CookieSessionStore, InvalidCookieName> {
    let active = Arc::new(active);
    let readers = MultiKeyDecryptor::new(vec![active.clone(), Arc::new(other)]);
    let sealer = AeadV1Sealer::new(MultiKeyCipher::new(active, readers));
    Ok(CookieSessionStore::builder()
        .sealer(sealer)
        .cookie_name("session".parse()?)
        .build())
}
```

Use the same sealer construction with `StoreBackedSessionStore::builder().sealer(...)`
for pointer cookies. This example changes keys by rebuilding and deploying the
engine; it does not reload secrets automatically. If you configured a separate
login-state sealer on the engine, rotate its keys with the same overlap procedure.

## Roll out in three stages

1. **Add the new reader everywhere.** Deploy with the old key active and both
   keys readable: `rotating_store(old_key, new_key)`. Wait until every replica
   can read cookies sealed by either key.
2. **Switch the writer.** Deploy with the new key active and both keys readable:
   `rotating_store(new_key, old_key)`. During rollout, either version can read
   the other's cookies. Keep cookie names, paths, and sealing format consistent.
3. **Retire the old reader after its acceptance window.** Count from the last
   time any replica could seal with the old key. Retain it for as long as those
   sessions and pending login flows must remain usable, including delivery and
   clock-skew allowances. Remove it earlier only if invalidating those cookies
   is intended.

Token refresh does not necessarily replace a store-backed pointer cookie. Do not
assume an active session has migrated to the new key merely because it refreshed.
If the deployment has no short absolute session cap, plan the retirement window
explicitly against cookie lifetime and the logout impact you accept.

## Verify before retiring a key

Keep a session created before rotation. Check it on every replica during both
rollout stages, then create a session with the new writer and check that too.
Start a login before the writer switch and finish its callback afterwards.

With `metrics` enabled, `huskarl.session_cookie.encrypt` reports the sealer's key
ID when available; decrypt counters report outcomes without key-ID labels.
Neither counter proves all old cookies have disappeared. See
[Cookie security](crate::_docs::explanation::cookie_security#cookie-encryption-key-rotation)
for how key-ID hints and fallback decryption work.
