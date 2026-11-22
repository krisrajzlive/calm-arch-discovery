---
system: payments-platform
environment: production
owner: "@payments-platform/architects"
---

# Payments platform: architecture

This document is the **approved architecture**. A change to it is a pull request that the
architecture group must approve (see `CODEOWNERS`). The tool reads only the tables under the
`Components`, `Connections`, `Controls` and `Waivers` headings; everything else is prose for
humans.

The CI gate rebuilds the architecture from the code and fails the build when the code no longer
conforms to the tables below.

## Context

Customers reach the storefront through a public gateway. The orders API owns order state in a
relational database, calls the payments service synchronously over mutual TLS, and the payments
service notifies customers through an asynchronous worker that calls back into the orders API.

`mail-relay` is a local-development helper (a fake SMTP server). It is deliberately not listed
here because it does not exist in production.

## Components

| id | type | owner | description |
|---|---|---|---|
| public-gateway | ingress | platform-edge | Internet-facing ingress; terminates TLS |
| storefront-web | webclient | web-experience | Browser storefront served behind the gateway |
| orders-api | service | orders-squad | Order lifecycle and checkout orchestration |
| payments-service | service | payments-core | Card authorisation and settlement |
| notification-worker | service | messaging-guild | Customer e-mail and SMS notifications |
| orders-db | database | data-platform | System of record for orders |
| cache | database | data-platform | Session and catalogue cache |

## Connections

| from | to | protocol | encrypted | purpose |
|---|---|---|---|---|
| public-gateway | storefront-web | HTTP | not-required | Serve the single-page app |
| public-gateway | orders-api | HTTP | not-required | Public order API |
| storefront-web | orders-api | HTTP | not-required | Browser calls the API |
| orders-api | orders-db | JDBC | required | Persist orders |
| orders-api | cache | TCP | required | Cache sessions and catalogue |
| orders-api | payments-service | mTLS | required | Authorise payments |
| payments-service | notification-worker | HTTP | not-required | Request customer notifications |
| notification-worker | orders-api | HTTPS | required | Report delivery status |

## Controls

| component | control |
|---|---|
| public-gateway | encryption-in-transit |
| storefront-web | container-hardening |
| orders-api | auth-required |
| orders-api | container-hardening |
| payments-service | auth-required |
| payments-service | container-hardening |
| payments-service | network-segmentation |
| notification-worker | container-hardening |
| orders-db | auth-required |
| orders-db | encryption-at-rest |
| orders-db | network-segmentation |
| cache | network-segmentation |

## Waivers

A waiver is a time-boxed, owned exception. It stops being honoured on the `expires` date and the
gate fails again, so debt cannot hide. The dates below are far out only so this fixture stays
green; real waivers should expire within a quarter.

| rule | subject | reason | owner | expires |
|---|---|---|---|---|
| encryption-violation | orders-api -> cache | Redis TLS rollout is tracked in PLAT-412 | @payments-platform/data-platform | 2029-12-31 |
| control-not-evidenced | notification-worker/container-hardening | Worker image still runs as root until PLAT-377 | @payments-platform/messaging-guild | 2029-12-31 |
| control-not-evidenced | cache/network-segmentation | NetworkPolicy for the cache lands with PLAT-415 | @payments-platform/data-platform | 2029-12-31 |
