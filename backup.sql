--
-- PostgreSQL database dump
--

-- Dumped from database version 17.2
-- Dumped by pg_dump version 17.2

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: get_next_user_id(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.get_next_user_id() RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    next_id INTEGER;
BEGIN
    -- Check for the first missing ID
    WITH missing_ids AS (
        SELECT generate_series(1, (SELECT COALESCE(MAX(id), 0) + 1 FROM "user")) AS id
    )
    SELECT id INTO next_id
    FROM missing_ids
    WHERE id NOT IN (SELECT id FROM "user")
    LIMIT 1;

    -- If no missing ID is found, return the next available ID (MAX(id) + 1)
    IF next_id IS NULL THEN
        SELECT COALESCE(MAX(id), 0) + 1 INTO next_id FROM "user";
    END IF;

    RETURN next_id;
END;
$$;


ALTER FUNCTION public.get_next_user_id() OWNER TO postgres;

--
-- Name: reorder_user_ids(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.reorder_user_ids() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    WITH ordered AS (
        SELECT id, ROW_NUMBER() OVER (ORDER BY id) AS new_id
        FROM "user"
    )
    UPDATE "user"
    SET id = ordered.new_id
    FROM ordered
    WHERE "user".id = ordered.id;

    -- ID sayac?n? guncelle
    PERFORM setval('user_id_seq', (SELECT MAX(id) FROM "user"));
    
    RETURN NULL;
END;
$$;


ALTER FUNCTION public.reorder_user_ids() OWNER TO postgres;

--
-- Name: user_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.user_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.user_id_seq OWNER TO postgres;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: user; Type: TABLE; Schema: public; Owner: superuser
--

CREATE TABLE public."user" (
    id integer DEFAULT nextval('public.user_id_seq'::regclass) NOT NULL,
    email character varying(120) NOT NULL,
    password character varying(255) NOT NULL,
    name character varying(120) NOT NULL,
    roles text[] NOT NULL,
    is_admin boolean NOT NULL,
    remaining_vacation_days integer DEFAULT 21 NOT NULL,
    reset_code character varying(6),
    reset_code_expiry timestamp without time zone
);


ALTER TABLE public."user" OWNER TO superuser;

--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: superuser
--

CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.users_id_seq OWNER TO superuser;

--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: superuser
--

ALTER SEQUENCE public.users_id_seq OWNED BY public."user".id;


--
-- Name: vacation_requests; Type: TABLE; Schema: public; Owner: superuser
--

CREATE TABLE public.vacation_requests (
    id integer NOT NULL,
    user_id integer NOT NULL,
    start_date date NOT NULL,
    end_date date NOT NULL,
    leave_reason character varying(50) NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL
);


ALTER TABLE public.vacation_requests OWNER TO superuser;

--
-- Name: vacation_requests_id_seq; Type: SEQUENCE; Schema: public; Owner: superuser
--

CREATE SEQUENCE public.vacation_requests_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.vacation_requests_id_seq OWNER TO superuser;

--
-- Name: vacation_requests_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: superuser
--

ALTER SEQUENCE public.vacation_requests_id_seq OWNED BY public.vacation_requests.id;


--
-- Name: vacation_requests id; Type: DEFAULT; Schema: public; Owner: superuser
--

ALTER TABLE ONLY public.vacation_requests ALTER COLUMN id SET DEFAULT nextval('public.vacation_requests_id_seq'::regclass);


--
-- Data for Name: user; Type: TABLE DATA; Schema: public; Owner: superuser
--

COPY public."user" (id, email, password, name, roles, is_admin, remaining_vacation_days, reset_code, reset_code_expiry) FROM stdin;
1	javidan.javadov@gmail.com	$2b$12$LbRzgkQq8d3P3sFJqMFlq.ygvR904j4bxjG9MwPZUtZqqiiKPlhTW	Javidan Javadov	{Employee}	f	21	\N	\N
2	zeuskingwarrior31169@gmail.com	$2b$12$NUwv9GLEFKcSxXi3Nqd7UeqwQP7rIz8slz5tbhqeetJEZHyW9sHpm	Javidan Javadov	{Employee}	f	21	\N	\N
3	admin@watermanage.com	$2b$12$wzB1aR9ZYGuM9mDwQrP8teGCAUDMgqe0MAoYsX4osqGGIhldO/Shm	Admin	{Manager}	t	21	\N	\N
4	javvidanjavadov@gmail.com	$2b$12$DuGZMMXr9d6vK3.ScwGTLe6fkieap7KuQzv7WNDhDefcvpW.3hDD.	Javidan Javadov	{Employee}	f	21	\N	\N
5	kjaskjkjaskj@gmail.com	$2b$12$ykCUH/xDKxuTZ3sua9oslOZBL55dc5XT7iUlspfRroaKcILNdQJZm	Cavidan Cavadov	{Employee}	f	21	\N	\N
6	testing2@gmail.com	$2b$12$fOIJI77TQITqzSfD06Lqe.N2Xb1vMUHOqRPBavesTtoXFMTsz/0Zu	2	{Employee}	f	21	\N	\N
7	testing01@gmail.com	$2b$12$dxhXvOzeUWXKDp4DG/M0xeDaooh6C6P1AfFK2ITP/hcP4Bw93CE86	Testing 01	{Employee}	f	21	\N	\N
8	javidan..javadov@gmail.com	$2b$12$jipmAIDVoT.4LS2LGavlCOUqOM31FcsBk4L2R1DlUeqsZe/gdqs86	Javidan Javadov	{Employee}	f	21	\N	\N
9	abdullahmemmedov@gmail.com	$2b$12$WwQxJNYffqLA0UC.bSEbuuwo0xSGS7qjpIEgwAL91KY0BIWFdwvza	Abdullah Mammadov	{Employee}	f	21	\N	\N
\.


--
-- Data for Name: vacation_requests; Type: TABLE DATA; Schema: public; Owner: superuser
--

COPY public.vacation_requests (id, user_id, start_date, end_date, leave_reason, status) FROM stdin;
1	5	2025-02-17	2025-02-19	family_emergency	Approved
2	5	2025-02-17	2025-02-22	study_leave	Rejected
3	5	2025-02-17	2025-02-22	study_leave	Cancelled
4	5	2025-02-19	2025-02-20	personal_reason	Rejected
5	5	2025-02-18	2025-02-19	personal_reason	Approved
55	9	2025-02-19	2025-02-21	sick_leave	Rejected
\.


--
-- Name: user_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.user_id_seq', 9, true);


--
-- Name: users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: superuser
--

SELECT pg_catalog.setval('public.users_id_seq', 6, false);


--
-- Name: vacation_requests_id_seq; Type: SEQUENCE SET; Schema: public; Owner: superuser
--

SELECT pg_catalog.setval('public.vacation_requests_id_seq', 55, true);


--
-- Name: user users_email_key; Type: CONSTRAINT; Schema: public; Owner: superuser
--

ALTER TABLE ONLY public."user"
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: user users_pkey; Type: CONSTRAINT; Schema: public; Owner: superuser
--

ALTER TABLE ONLY public."user"
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: vacation_requests vacation_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: superuser
--

ALTER TABLE ONLY public.vacation_requests
    ADD CONSTRAINT vacation_requests_pkey PRIMARY KEY (id);


--
-- Name: user auto_reorder_ids; Type: TRIGGER; Schema: public; Owner: superuser
--

CREATE TRIGGER auto_reorder_ids AFTER INSERT OR DELETE ON public."user" FOR EACH STATEMENT EXECUTE FUNCTION public.reorder_user_ids();


--
-- Name: vacation_requests vacation_requests_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: superuser
--

ALTER TABLE ONLY public.vacation_requests
    ADD CONSTRAINT vacation_requests_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- PostgreSQL database dump complete
--

