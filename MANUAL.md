# Tigress Rights — Programmer's Manual

## Overview

`tigress/rights` is a **role- and permission-based access control** module for the Tigress Framework (PHP 8.5+). It supports two complementary authorization strategies:

1. **Level-based rights** — an integer hierarchy (`access_level`) checked against route-level whitelists.
2. **Special (tool-based) rights** — per-user, per-tool granular CRUD permissions stored in a `system_rights` database table.

Routes can use **wildcards** for dynamic segments (e.g. `/users/{id}` → `/users/*`) and **inherit** rights from parent paths when no explicit rights are defined.

---

## Classes

### `Tigress\Rights` (`src/Rights.php`)

The main entry point. Instantiate it once and configure routes via `setRights()`, then check access with `checkRights()` or `checkRightsForSpecificPath()`.

### `Repository\SystemRightsRepo` (`src/repositories/SystemRightsRepo.php`)

Repository for the `system_rights` database table (composite primary key: `user_id` + `tool`). Used internally to persist and query special rights.

---

## Setup

### 1. Route Registration

Define route objects with the following properties:

| Property | Type | Required | Description |
|---|---|---|---|
| `path` | `string` | **yes** | URL path, may contain `{param}` placeholders |
| `request` | `string` | no | HTTP method (`GET`, `POST`, etc.); defaults to `GET` |
| `level_rights` | `int[]` | no | Allowed `access_level` values (empty = everyone allowed) |
| `special_rights` | `string` | no | Tool name key for per-user special rights lookup |
| `special_rights_default` | `int[]` | no | Default `access_level` values that auto-grant all special rights for this tool |

Example route definition:
```php
$routes = [
    (object) [
        'path' => '/dashboard',
        'request' => 'GET',
        'level_rights' => [1, 2, 3, 100],
    ],
    (object) [
        'path' => '/admin/users/{id}',
        'request' => 'GET',
        'level_rights' => [100],
        'special_rights' => 'users',
        'special_rights_default' => [1, 2],
    ],
    (object) [
        'path' => '/https://external.example.com/callback',
        'request' => 'GET',
        // no level_rights → accessible to all authenticated users
    ],
];
```

### 2. Configure the Rights Instance

```php
$rights = new \Tigress\Rights();
$rights->setRights($routes);
```

`setRights()` does two things:

- **Phase 1** — builds an internal `accessList` from every route that has at least one rights property defined.
- **Phase 2** — for routes that have **no** rights at all, walks up the path hierarchy looking for the nearest parent with rights and **inherits** them.

> **Inheritance example:** If `/admin` has `level_rights: [100]` and `/admin/logs` has no rights defined, `/admin/logs` will inherit `[100]` from `/admin`.

### 3. Session Expectations

The module reads from `$_SESSION`:

| Key | Type | Description |
|---|---|---|
| `$_SESSION['user']['id']` | `int` | Logged-in user's ID |
| `$_SESSION['user']['access_level']` | `int` | User's access level (≤ 0 → denied) |
| `$_SESSION['userRights']` | `array` | Populated automatically by `checkRights()`, keyed by tool name |

The constant `RIGHTS` should be available in your application (pointing to the Rights instance), as used by `checkRights()`.

---

## Checking Access

### Automatically (from `$_SERVER['REQUEST_URI']`)

```php
$allowed = $rights->checkRights($action = 'access');
```

- Reads the current request URI and HTTP method from the server globals.
- Loads the user's special rights into `$_SESSION['userRights']` if the user is logged in.
- Returns `true`/`false`.

### For a Specific Path

```php
$allowed = $rights->checkRightsForSpecificPath(
    path: '/admin/users/42',
    action: 'write',
    requestMethod: 'POST'
);
```

- Useful for checking access to arbitrary paths (e.g. in middleware or Twig helpers).

---

## How Authorization Is Decided

`processCheckRights()` runs this logic:

1. **User must be authenticated** — `$_SESSION['user']['access_level'] > 0`.
2. **Route matching** — iterates the `accessList`; path patterns use `{param}` → `*` → regex with `([^/]+)`.
3. **No match found** → allow only if the path begins with `http://` or `https://` (external redirects).
4. **Match found** → grant access if **any** of these is true:
   - `level_rights` is empty (open to all authenticated users), OR
   - user's `access_level` is in `level_rights`, OR
   - user's `access_level` is `100` (super-admin), OR
   - the route has `special_rights`, the user has an entry for that tool in `$_SESSION['userRights']`, AND the requested `$action` is `1` (true).

---

## Managing Special Rights

### Assign (or Update) Rights for a User + Tool

```php
$rights->setSystemRights($user, 'users', [
    'access' => 1,
    'read'   => 1,
    'write'  => 0,
    'delete' => 0,
]);
```

- If the user is inactive (`$user->active != 1`), it sets `$_SESSION['error']` and skips.
- Default rights are `[access:1, read:1, write:1, delete:1]` if `$rights` is `null`.

### Remove All Rights for a User + Tool

```php
$rights->removeSystemRights($user, 'users');
```

Deletes the `system_rights` row for that user/tool pair.

### Retrieve Special Rights for a User

```php
$userRights = \Tigress\Rights::getSpecialRights($userId);
// Returns: [ 'toolName' => ['access' => 1, 'read' => 1, 'write' => 0, 'delete' => 0], ... ]
```

This is a **static** method. It is also called internally from `checkRights()`.

---

## SystemRightsRepo Methods

These are used internally but may also be called directly:

| Method | Purpose |
|---|---|
| `updateRightsUser(jsonMenuFile, id, recht)` | Bulk-replaces all special rights for a user based on a menu JSON and their access level. Deletes existing rows, then inserts matching ones. |
| `createSecurityMatrix(jsonMenuFile)` | Reads a menu JSON file (`SYSTEM_ROOT/src/menus/...`) and builds a matrix of URL → rights definitions from the access list. |
| `getRightsByUserId(id)` | Returns all special rights for a user as an associative array. |

---

## Path Inheritance Rules

- Trailing slashes are **stripped** for consistency.
- When checking rights, the code looks for an **exact** `accessList` entry matching the path + request method.
- If no match is found for the path itself, it **walks up** the path segments via `getFirstParentWithRights()` until it finds a parent with defined rights or reaches root.
- Example: `/admin/users/create` → check `/admin/users` → check `/admin` → check root → `null`.

---

## Remarks

### Authentication Notice

`checkRights()` loads special rights into the session **only** when `$_SESSION['user']['id']` is set. If your application's `Users` class isn't loaded yet (or the user isn't logged in), the method returns `false`. Call `getSpecialRights()` manually if you need rights outside of `checkRights()`.

### External URLs

Paths matching `http://...` or `https://...` are **allowed by default** when no route matches, under the assumption they are external redirects. To restrict them, add explicit route entries.

### `RIGHTS` Constant

The code references a global `RIGHTS` constant (in `checkRights()` and `SystemRightsRepo::createSecurityMatrix()`). Ensure your application defines:
```php
define('RIGHTS', $rightsInstance);
```
or adjust the code to use a different mechanism.
