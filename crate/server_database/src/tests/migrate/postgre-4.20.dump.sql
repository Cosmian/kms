--
-- PostgreSQL database dump
--

-- Dumped from database version 16.2 (Debian 16.2-1.pgdg120+2)
-- Dumped by pg_dump version 16.2 (Debian 16.2-1.pgdg120+2)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: objects; Type: TABLE; Schema: public; Owner: kms
--

CREATE TABLE public.objects (
    id character varying(40) NOT NULL,
    object json NOT NULL,
    attributes json NOT NULL,
    state character varying(32),
    owner character varying(255)
);


ALTER TABLE public.objects OWNER TO kms;

--
-- Name: parameters; Type: TABLE; Schema: public; Owner: kms
--

CREATE TABLE public.parameters (
    name character varying(40) NOT NULL,
    value character varying(256)
);


ALTER TABLE public.parameters OWNER TO kms;

--
-- Name: read_access; Type: TABLE; Schema: public; Owner: kms
--

CREATE TABLE public.read_access (
    id character varying(40),
    userid character varying(255),
    permissions json NOT NULL
);


ALTER TABLE public.read_access OWNER TO kms;

--
-- Name: tags; Type: TABLE; Schema: public; Owner: kms
--

CREATE TABLE public.tags (
    id character varying(40),
    tag character varying(255)
);


ALTER TABLE public.tags OWNER TO kms;

--
-- Data for Name: objects; Type: TABLE DATA; Schema: public; Owner: kms
--

COPY public.objects (id, object, attributes, state, owner) FROM stdin;
1d21745b-89ca-419a-8f39-e01d9ceaf442	{"object": {"KeyBlock": {"KeyValue": {"Attributes": {"ObjectType": "SymmetricKey", "KeyFormatType": "TransparentSymmetricKey", "CryptographicLength": 256, "CryptographicAlgorithm": "AES", "CryptographicUsageMask": 2108}, "KeyMaterial": {"Key": [91, 85, 43, 159, 138, 103, 219, 42, 253, 18, 155, 75, 53, 230, 200, 127, 126, 37, 200, 104, 240, 27, 97, 56, 213, 61, 151, 209, 193, 102, 68, 109]}}, "KeyFormatType": "TransparentSymmetricKey", "CryptographicLength": 256, "CryptographicAlgorithm": "AES"}}, "object_type": "SymmetricKey"}	{"ObjectType": "SymmetricKey", "KeyFormatType": "TransparentSymmetricKey", "CryptographicLength": 256, "CryptographicAlgorithm": "AES", "CryptographicUsageMask": 2108}	Active	883b0867-ddf1-4d86-9d05-5d6ad97f50bd
a57d054b-dded-4331-b0c5-07313127d519	{"object": {"KeyBlock": {"KeyValue": {"Attributes": {"ObjectType": "SymmetricKey", "KeyFormatType": "TransparentSymmetricKey", "CryptographicLength": 256, "CryptographicAlgorithm": "AES", "CryptographicUsageMask": 2108}, "KeyMaterial": {"Key": [165, 252, 62, 60, 97, 77, 163, 247, 199, 45, 117, 92, 183, 146, 232, 230, 74, 167, 29, 236, 51, 23, 101, 184, 57, 49, 116, 62, 131, 204, 41, 99]}}, "KeyFormatType": "TransparentSymmetricKey", "CryptographicLength": 256, "CryptographicAlgorithm": "AES"}}, "object_type": "SymmetricKey"}	{"ObjectType": "SymmetricKey", "KeyFormatType": "TransparentSymmetricKey", "CryptographicLength": 256, "CryptographicAlgorithm": "AES", "CryptographicUsageMask": 2108}	Active	883b0867-ddf1-4d86-9d05-5d6ad97f50bd
\.


--
-- Data for Name: parameters; Type: TABLE DATA; Schema: public; Owner: kms
--

COPY public.parameters (name, value) FROM stdin;
db_state	"upgrading"
\.


--
-- Data for Name: read_access; Type: TABLE DATA; Schema: public; Owner: kms
--

COPY public.read_access (id, userid, permissions) FROM stdin;
\.


--
-- Data for Name: tags; Type: TABLE DATA; Schema: public; Owner: kms
--

COPY public.tags (id, tag) FROM stdin;
1d21745b-89ca-419a-8f39-e01d9ceaf442	0a515518-3369-4413-aa8f-938a6b057caa
a57d054b-dded-4331-b0c5-07313127d519	0a515518-3369-4413-aa8f-938a6b057caa
a57d054b-dded-4331-b0c5-07313127d519	237fba3c-e567-478f-b5e9-e275447058f9
\.


--
-- Name: objects objects_pkey; Type: CONSTRAINT; Schema: public; Owner: kms
--

ALTER TABLE ONLY public.objects
    ADD CONSTRAINT objects_pkey PRIMARY KEY (id);


--
-- Name: parameters parameters_pkey; Type: CONSTRAINT; Schema: public; Owner: kms
--

ALTER TABLE ONLY public.parameters
    ADD CONSTRAINT parameters_pkey PRIMARY KEY (name);


--
-- Name: read_access read_access_id_userid_key; Type: CONSTRAINT; Schema: public; Owner: kms
--

ALTER TABLE ONLY public.read_access
    ADD CONSTRAINT read_access_id_userid_key UNIQUE (id, userid);


--
-- Name: tags tags_id_tag_key; Type: CONSTRAINT; Schema: public; Owner: kms
--

ALTER TABLE ONLY public.tags
    ADD CONSTRAINT tags_id_tag_key UNIQUE (id, tag);


--
-- PostgreSQL database dump complete
--

