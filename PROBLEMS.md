# Code Problems — `src/`

## Critical (crashes at runtime)

### `database.py`

**1. `getPasswordLogs` and `deletePasswordLogs` don't exist**
`app.py:343` and `app.py:352` call `database.getPasswordLogs(...)` and `database.deletePasswordLogs(...)`. Neither method is defined in `Database`. The `/moreInfo` route crashes on every request.

**2. `addPassword` sets status on the class, not the instance**
```python
# Wrong — mutates the class attribute for all rows
Passwords.status = True
Passwords.timesLeaked = int(msg)
# Should be:
nova_senha.status = True
```

**3. `timesLeaked` column doesn't exist**
Referenced in `addPassword`, `updatePassword`, and `updatePasswordStatus` but never declared as a column in the `Passwords` model. Any write crashes with an `AttributeError`.

**4. `Passwords.strength` and `Passwords.name` don't exist**
`getPasswords` (line ~1365 and ~1378) references `Passwords.strength` and `Passwords.name` for sorting/filtering. Neither column is defined in the model.

**5. All `/api` route handlers call undefined functions**
`api/index.py` calls `getUserByEmail`, `verifyPassword`, `updateLastLogin`, `logSecurityEvent`, `getUserPasswords`, `getPasswordById`, `decryptPasswordData`, `updatePasswordUsage`, `generateSecurePassword`, `calculatePasswordStrength` — none are defined anywhere. Every `/api/*` endpoint that exercises these will raise `NameError` and 500.

**6. `updateUser` called with `profilePic` kwarg that doesn't exist**
`app.py:306` calls `database.updateUser(..., profilePic=profilePic)` but the method signature is `(self, id, login, password, role)`. Python raises `TypeError` on every account save.

**7. `checkPasswordPwned` returns a plain string on exception**
```python
except Exception as e:
    return f'{type(e).__name__}: ...'  # Missing tuple!
    # Should be: return False, f'...'
```
Callers unpack `leak, msg = self.checkPasswordPwned(...)` — this crashes with `ValueError: not enough values to unpack`.

---

### `app.py`

**8. Wrong return-value check for `getUsers`**
```python
# app.py:123-131
users = database.getUsers(...)  # returns (bool, data) tuple
if users == False:     # always False — tuple != False
elif users == True:    # always False
```
Should be `success, users = database.getUsers(...)`.

**9. `onlySys` decorator missing `@login_required`**
If an unauthenticated request hits a route decorated with `@onlySys`, `current_user.role` raises `AttributeError` because `current_user` is the anonymous user proxy.

**10. `config.json` opened with hardcoded relative path**
```python
ITEM_CONFIGS = json.load(open('./src/config.json', 'r'))
```
Breaks if the working directory is not the repo root (e.g., when Vercel runs it).

---

### `cryptograph.py`

**11. Static methods missing `@staticmethod`**
`keyGenerator`, `encryptSentence`, `decryptSentence` are defined as `def method(arg):` (no `self`) but without `@staticmethod`. Called as `Cryptograph.keyGenerator(key)` — works on class-level call but calling on an instance passes the instance as the first arg and shifts all parameters.

**12. `encryptPass` returns a tuple on exception instead of `str`**
```python
except Exception as e:
    return False, f'...'  # Caller expects a str (hash)
```
Callers like `User(password=self.iscryptograph.encryptPass(password))` store the tuple `(False, "...")` as the password hash, breaking all future logins.

---

## High (wrong behavior / security)

**13. `script.js` contains Jinja2 syntax — never rendered**
```js
let currentUserRole = "{{ current_user.role if current_user.is_authenticated else 'guest' }}";
```
Flask does not render static `.js` files as templates. This string is served literally, so `currentUserRole` is always the raw Jinja2 expression string, making `updateDashboardView()` always show the wrong panel.

**14. Extension `popup.js` "encrypts" passwords with `btoa`**
```js
async function encryptPassword(password) {
    return btoa(password);  // base64, not encryption
}
```
Passwords stored in `chrome.storage.local` are effectively plaintext.

**15. Extension `popup.js` is fully disconnected from the backend**
`popup.js` reads/writes only to `chrome.storage.local`. It never calls the Flask API. Data saved in the popup is never synced to the server and vice-versa. `background.js` talks to the API but `popup.js` doesn't.

**16. `background.js` hardcodes `localhost` as API URL**
```js
const API_BASE_URL = 'http://localhost:5000/api';
```
The production extension points to localhost — it will fail for any real user.

**17. `viewPasswordModal` exposes plaintext password in DOM attribute**
`data-pass="{{ password.password }}"` puts the decrypted password in the HTML source, visible in DevTools and accessible to any XSS or browser extension.

**18. `background.js` uses `Math.random()` for password generation**
`generateSecurePasswordLocal` uses `Math.floor(Math.random() * ...)` — not cryptographically random. Should use `crypto.getRandomValues()`.

**19. `setInterval` in MV3 service worker**
`background.js` uses two `setInterval` calls (token check, backup). MV3 service workers are not persistent — they terminate when idle. `setInterval` is unreliable and will silently stop working.

**20. `JWT_SECRET` has a weak hardcoded fallback**
```python
JWT_SECRET = os.getenv('JWT_SECRET', 'sua-chave-secreta-aqui')
```
If `JWT_SECRET` is not set, any attacker can forge valid JWTs.

**21. Extension `popup.js` hashes passwords with unsalted SHA-256**
`hashPassword` uses `crypto.subtle.digest('SHA-256', ...)` with no salt, making stored local user credentials trivially reversible via rainbow tables.

**22. DELETE `/moreInfo` — JS sends logs as comma-joined string, backend reads as list**
JS: `body: new URLSearchParams({'logs': selectedLogs.join(',')})` sends `logs=1,2,3`.
Python: `request.form.getlist('logs')` returns `['1,2,3']` not `['1','2','3']`. Log deletion silently fails to find any log IDs.

---

## Medium (broken logic / incomplete)

**23. `findUserLogin` uses `filter_by(login=login)` on a hybrid property**
`filter_by` doesn't trigger the `LoginComparator`. Should use `.filter(User.login == login)` to go through the hash-based comparator.

**24. `getMostUsedPasswords` passes user `id` as Fernet key**
```python
Cryptograph.decryptSentence(password.password, id)
```
`id` is a UUID string, not a derived Fernet key. Decryption always fails.

**25. `getLeakedPasswords` and `getMostUsedPasswords` use wrong column name**
Both filter with `filter_by(user_id=id)` but the model column is `userId`. SQLAlchemy silently returns no rows.

**26. `getDashboardInfo` for `super` role returns empty dict**
```python
if user.role == 'super':
    return True, {}
```
Incomplete placeholder.

**27. `createSysadmin` swallows its return value**
On exception it `return -1, '...'` but the caller doesn't capture it. More importantly, it runs on every app startup attempting to insert a duplicate user, hitting the DB with a failing transaction each time. Should check for existence first.

**28. `updatePasswordStatus` uses old decryption API**
```python
self.cryptograph.decryptSentence(credential.password, key)
```
All other code now uses the hybrid property getter. This method uses the old direct API with an incompatible key format.

**29. `icecream` debug statements left in production**
`ic(flagId)` in `app.py:deleteFlag` and `from icecream import ic` in `database.py`. `icecream` is not in `requirements.txt`, so this crashes on import if not installed.

**30. `/forgotPassword` doesn't send any email**
Returns "Instruções enviadas para o email cadastrado" but there is no email-sending implementation.

**31. `Filters.flags` relationship points to `Filters` itself**
```python
flags = Config.db.relationship('Filters', secondary=PasswordFlags.__table__, ...)
```
The primary model should be `Passwords`, not `Filters`. This self-referential relationship is wrong.

---

## Low (code quality / minor)

**32. `canHandle` decorator signature is never matched**
The decorator wraps `getUsers` and `getPasswords` but expects `(self, userId, itemType, method, item, *args, **kwargs)` as positional args. The actual calls pass `userId`, `itemType`, `method` as keyword args, so the decorator's positional unpacking always uses defaults (`None`), and the access control logic never runs.

**33. `Logs` model defined but no methods to query or delete logs**
`getPasswordLogs` / `deletePasswordLogs` are missing (see #1), but the `Logs` model also has no foreign-key cascade delete defined, so deleting a `Passwords` row will leave orphaned `Logs` rows or crash with a FK constraint error.

**34. `api/index.py` `/flags/*` routes duplicate web routes without implementation**
`/api/flags/add`, `/api/flags/delete` return hardcoded stub responses. The web routes in `app.py` already handle flags properly.

**35. `background.js` "backup" interval does nothing**
The hourly `setInterval` just logs `'Backup de configurações realizado'` without actually backing up anything.

**36. `popup.js` `loadSettings` crashes if DOM elements don't exist**
`document.getElementById('autoFill').checked = ...` — if `popup.html` doesn't have those elements in the current view, this throws `Cannot set properties of null`.
