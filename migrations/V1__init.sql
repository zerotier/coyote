create table nonces (
  nonce varchar primary key
);
--
create table jwks (
  id serial primary key,
  nonce_key varchar not null unique,
  alg varchar not null,
  -- base64'd public key components
  n varchar,
  e varchar,
  x varchar,
  y varchar,

  created_at timestamptz default CURRENT_TIMESTAMP not null,
  deleted_at timestamptz,

  CHECK((n is not null and e is not null) or (x is not null and y is not null))
);
--
create table accounts (
  id serial primary key,
  jwk_id integer not null,
  orders_nonce varchar not null unique,
  -- TODO: external accounts

  created_at timestamptz default CURRENT_TIMESTAMP not null,
  deleted_at timestamptz
);
--
create table contacts (
  id serial primary key,
  account_id integer not null,
  contact varchar not null,

  created_at timestamptz default CURRENT_TIMESTAMP not null,
  deleted_at timestamptz,

  UNIQUE (account_id, contact)
);
--
create table orders_challenges (
  id serial primary key,
  order_id varchar not null,
  authorization_id varchar not null,
  challenge_type varchar not null,
  reference varchar not null unique,
  identifier varchar not null,
  token varchar not null,
  status varchar not null,
  issuing_address varchar not null,
  validated timestamptz,
  created_at timestamptz default CURRENT_TIMESTAMP not null,
  deleted_at timestamptz
);
--
create table orders_authorizations (
  id serial primary key,
  order_id varchar not null,
  identifier varchar not null,
  reference varchar not null unique,
  expires timestamptz not null,
  created_at timestamptz default CURRENT_TIMESTAMP not null,
  deleted_at timestamptz
);
--
create table orders_certificate (
  id serial primary key,
  order_id varchar not null unique,
  reference varchar not null unique,
  certificate bytea not null,
  created_at timestamptz default CURRENT_TIMESTAMP not null,
  deleted_at timestamptz
);
--
create table orders (
  id serial primary key,
  order_id varchar not null unique, -- this is the *public* order id. it is not the primary key used in the db.
  expires timestamptz,
  not_before timestamptz default CURRENT_TIMESTAMP,
  not_after timestamptz,
  error text,
  finalized bool not null,

  created_at timestamptz default CURRENT_TIMESTAMP not null,
  deleted_at timestamptz
);
