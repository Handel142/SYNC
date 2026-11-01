-- SYNC 2.0 multiplayer schema. Run once in Supabase SQL Editor.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
 id uuid primary key references auth.users(id) on delete cascade,
 username text not null unique,
 avatar_key text not null default 'orbit' check (avatar_key in ('orbit','comet','nova','pulse','pixel','spark')),
 total_xp integer not null default 0, games_played integer not null default 0,
 created_at timestamptz not null default now()
);
alter table public.profiles add column if not exists total_xp integer not null default 0;
alter table public.profiles add column if not exists games_played integer not null default 0;

create table if not exists public.challenges (
 id uuid primary key default gen_random_uuid(),
 mode text not null check(mode in ('duel','together','mystery','daily')),
 category text not null, difficulty text not null default 'easy',
 prompt text not null, options jsonb not null default '[]'::jsonb,
 answer text not null, explanation text not null default '',
 clue_map jsonb not null default '{}'::jsonb, active boolean not null default true
);
create table if not exists public.rooms (
 id uuid primary key default gen_random_uuid(), code text not null unique,
 host_id uuid not null references auth.users(id),
 mode text not null check(mode in ('duel','together','mystery')),
 status text not null default 'waiting' check(status in ('waiting','ready','playing','completed','cancelled')),
 max_players int not null check(max_players between 2 and 8),
 rounds_total int not null check(rounds_total between 1 and 10),
 current_round int not null default 0, current_challenge_id uuid references public.challenges(id),
 round_deadline timestamptz, created_at timestamptz not null default now(),
 expires_at timestamptz not null default now()+interval '2 hours'
);
create table if not exists public.room_players (
 room_id uuid not null references public.rooms(id) on delete cascade,
 user_id uuid not null references auth.users(id) on delete cascade,
 seat int not null check(seat between 1 and 8), is_ready boolean not null default false,
 connected boolean not null default true, joined_at timestamptz not null default now(),
 primary key(room_id,user_id), unique(room_id,seat)
);
create table if not exists public.matches (
 id uuid primary key default gen_random_uuid(), room_id uuid not null references public.rooms(id),
 mode text not null, status text not null default 'playing', started_at timestamptz not null default now(),
 completed_at timestamptz
);
create table if not exists public.match_rounds (
 id uuid primary key default gen_random_uuid(), match_id uuid not null references public.matches(id) on delete cascade,
 round_number int not null, challenge_id uuid not null references public.challenges(id),
 deadline_at timestamptz not null, completed_at timestamptz, unique(match_id,round_number)
);
create table if not exists public.submissions (
 id uuid primary key default gen_random_uuid(), round_id uuid not null references public.match_rounds(id) on delete cascade,
 user_id uuid not null references auth.users(id), answer text not null, correct boolean not null,
 points int not null default 0, submitted_at timestamptz not null default now(), unique(round_id,user_id)
);
create table if not exists public.player_match_stats (
 match_id uuid not null references public.matches(id) on delete cascade,
 user_id uuid not null references auth.users(id), points int not null default 0,
 correct_answers int not null default 0, primary key(match_id,user_id)
);
create table if not exists public.daily_challenges (
 challenge_date date primary key, challenge_id uuid not null references public.challenges(id)
);
create table if not exists public.daily_attempts (
 challenge_date date not null references public.daily_challenges(challenge_date),
 user_id uuid not null references auth.users(id), answer text not null, correct boolean not null,
 points int not null default 0, submitted_at timestamptz not null default now(), primary key(challenge_date,user_id)
);

create index if not exists room_players_user_idx on public.room_players(user_id);
create index if not exists room_code_status_idx on public.rooms(code,status);

-- Membership helper is SECURITY DEFINER to avoid recursive RLS policy evaluation.
create or replace function public.is_room_member(p_room uuid)
returns boolean language sql stable security definer set search_path=public
as $$ select exists(select 1 from public.room_players where room_id=p_room and user_id=auth.uid()) $$;

alter table public.profiles enable row level security;
alter table public.challenges enable row level security;
alter table public.rooms enable row level security;
alter table public.room_players enable row level security;
alter table public.matches enable row level security;
alter table public.match_rounds enable row level security;
alter table public.submissions enable row level security;
alter table public.player_match_stats enable row level security;
alter table public.daily_challenges enable row level security;
alter table public.daily_attempts enable row level security;

drop policy if exists profile_self on public.profiles;
create policy profile_self on public.profiles for select to authenticated using(id=auth.uid());
drop policy if exists room_member_read on public.rooms;
create policy room_member_read on public.rooms for select to authenticated using(public.is_room_member(id));
drop policy if exists players_member_read on public.room_players;
create policy players_member_read on public.room_players for select to authenticated using(public.is_room_member(room_id));
drop policy if exists matches_member_read on public.matches;
create policy matches_member_read on public.matches for select to authenticated using(public.is_room_member(room_id));
drop policy if exists rounds_member_read on public.match_rounds;
create policy rounds_member_read on public.match_rounds for select to authenticated using(exists(select 1 from public.matches m where m.id=match_id and public.is_room_member(m.room_id)));
drop policy if exists stats_member_read on public.player_match_stats;
create policy stats_member_read on public.player_match_stats for select to authenticated using(exists(select 1 from public.matches m where m.id=match_id and public.is_room_member(m.room_id)));
drop policy if exists submissions_self_read on public.submissions;
create policy submissions_self_read on public.submissions for select to authenticated using(user_id=auth.uid());
drop policy if exists daily_self_read on public.daily_attempts;
create policy daily_self_read on public.daily_attempts for select to authenticated using(user_id=auth.uid());
revoke all on public.challenges from anon,authenticated;
revoke all on public.rooms,public.room_players,public.matches,public.match_rounds,public.submissions,public.player_match_stats,public.daily_attempts from anon,authenticated;
revoke all on public.profiles from anon,authenticated;
grant select on public.profiles,public.rooms,public.room_players,public.matches,public.player_match_stats to authenticated;

create or replace function public.save_my_profile(p_username text,p_avatar text)
returns public.profiles language plpgsql security definer set search_path=public as $$
declare x public.profiles;
begin
 if auth.uid() is null then raise exception 'Sign in first'; end if;
 if p_username !~ '^[A-Za-z0-9_]{3,18}$' then raise exception 'Username must be 3–18 letters, numbers or underscores'; end if;
 if p_avatar not in ('orbit','comet','nova','pulse','pixel','spark') then raise exception 'Invalid avatar'; end if;
 if exists(select 1 from profiles where lower(username)=lower(p_username) and id<>auth.uid()) then raise exception 'That username is already taken'; end if;
 insert into profiles(id,username,avatar_key) values(auth.uid(),p_username,p_avatar)
 on conflict(id) do update set username=excluded.username,avatar_key=excluded.avatar_key returning * into x;
 return x;
end $$;

create or replace function public.create_room(p_mode text,p_max_players int,p_rounds int)
returns public.rooms language plpgsql security definer set search_path=public as $$
declare x public.rooms; c text; n int:=0;
begin
 if auth.uid() is null or not exists(select 1 from profiles where id=auth.uid()) then raise exception 'Create your player profile first'; end if;
 if p_mode not in ('duel','together','mystery') or p_max_players not between 2 and 8 or p_rounds not between 1 and 10 then raise exception 'Invalid room settings'; end if;
 loop c:=upper(substr(encode(gen_random_bytes(8),'hex'),1,6)); n:=n+1; exit when not exists(select 1 from rooms where code=c); if n>10 then raise exception 'Could not generate room code'; end if; end loop;
 insert into rooms(code,host_id,mode,max_players,rounds_total) values(c,auth.uid(),p_mode,p_max_players,p_rounds) returning * into x;
 insert into room_players(room_id,user_id,seat,is_ready) values(x.id,auth.uid(),1,true);
 return x;
end $$;

create or replace function public.join_room(p_code text)
returns public.rooms language plpgsql security definer set search_path=public as $$
declare x public.rooms; s int;
begin
 if auth.uid() is null or not exists(select 1 from profiles where id=auth.uid()) then raise exception 'Create your player profile first'; end if;
 select * into x from rooms where code=upper(trim(p_code)) and status in ('waiting','ready') and expires_at>now() for update;
 if not found then raise exception 'Room not found, expired, full or already playing'; end if;
 if exists(select 1 from room_players where room_id=x.id and user_id=auth.uid()) then return x; end if;
 select coalesce(max(seat),0)+1 into s from room_players where room_id=x.id;
 if s>x.max_players then raise exception 'Room is full'; end if;
 insert into room_players(room_id,user_id,seat) values(x.id,auth.uid(),s);
 update rooms set status='waiting' where id=x.id;
 return x;
end $$;

create or replace function public.set_room_ready(p_room uuid,p_ready boolean)
returns void language plpgsql security definer set search_path=public as $$
begin
 if not public.is_room_member(p_room) then raise exception 'Not a room member'; end if;
 if (select status from rooms where id=p_room) not in ('waiting','ready') then raise exception 'Room already started'; end if;
 update room_players set is_ready=p_ready where room_id=p_room and user_id=auth.uid();
 update rooms set status=case when (select count(*) from room_players where room_id=p_room)>=2 and (select bool_and(is_ready) from room_players where room_id=p_room) then 'ready' else 'waiting' end where id=p_room;
end $$;

create or replace function public.get_room_lobby(p_room uuid)
returns jsonb language plpgsql security definer set search_path=public as $$
declare j jsonb;
begin
 if not public.is_room_member(p_room) then raise exception 'Not a room member'; end if;
 select jsonb_build_object('room',(select to_jsonb(r)-'current_challenge_id' from rooms r where id=p_room),'players',coalesce((select jsonb_agg(jsonb_build_object('user_id',rp.user_id,'seat',rp.seat,'is_ready',rp.is_ready,'connected',rp.connected,'username',p.username,'avatar_key',p.avatar_key) order by rp.seat) from room_players rp join profiles p on p.id=rp.user_id where rp.room_id=p_room),'[]'::jsonb),'my_user_id',auth.uid()) into j;
 return j;
end $$;

create or replace function public.start_match(p_room uuid)
returns uuid language plpgsql security definer set search_path=public as $$
declare r public.rooms; m public.matches; i int; c uuid;
begin
 select * into r from rooms where id=p_room for update;
 if not found or r.host_id<>auth.uid() then raise exception 'Only the room host can start'; end if;
 if r.status not in ('ready','waiting') or (select count(*) from room_players where room_id=p_room)<2 then raise exception 'At least two players are required'; end if;
 if not (select bool_and(is_ready) from room_players where room_id=p_room) then raise exception 'Everyone must be ready'; end if;
 if (select count(*) from challenges where mode=r.mode and active)<r.rounds_total then raise exception 'Not enough challenges for this mode'; end if;
 insert into matches(room_id,mode) values(p_room,r.mode) returning * into m;
 for i in 1..r.rounds_total loop
  select id into c from challenges where mode=r.mode and active order by random() offset (i-1) limit 1;
  insert into match_rounds(match_id,round_number,challenge_id,deadline_at) values(m.id,i,c,now()+interval '90 seconds');
 end loop;
 select challenge_id into c from match_rounds where match_id=m.id and round_number=1;
 update rooms set status='playing',current_round=1,current_challenge_id=c,round_deadline=now()+interval '90 seconds' where id=p_room;
 insert into player_match_stats(match_id,user_id) select m.id,user_id from room_players where room_id=p_room;
 return m.id;
end $$;

create or replace function public.get_room_challenge(p_room uuid)
returns jsonb language plpgsql security definer set search_path=public as $$
declare r public.rooms; c public.challenges; s int;
begin
 if not public.is_room_member(p_room) then raise exception 'Not a room member'; end if;
 select * into r from rooms where id=p_room;
 if r.status<>'playing' or r.current_challenge_id is null then raise exception 'No active challenge'; end if;
 select * into c from challenges where id=r.current_challenge_id;
 select seat into s from room_players where room_id=p_room and user_id=auth.uid();
 return jsonb_build_object('category',c.category,'difficulty',c.difficulty,'prompt',c.prompt,'options',c.options,'clue',coalesce(c.clue_map->>s::text,c.explanation),'round_number',r.current_round,'rounds_total',r.rounds_total,'deadline',r.round_deadline,'mode',r.mode);
end $$;

create or replace function public.submit_room_answer(p_room uuid,p_answer text)
returns jsonb language plpgsql security definer set search_path=public as $$
declare r public.rooms; m public.matches; mr public.match_rounds; c public.challenges; ok boolean; pts int:=0; done int; total int;
begin
 if not public.is_room_member(p_room) then raise exception 'Not a room member'; end if;
 select * into r from rooms where id=p_room for update;
 if r.status<>'playing' or now()>r.round_deadline then raise exception 'Round is not accepting answers'; end if;
 select * into m from matches where room_id=p_room and status='playing' order by started_at desc limit 1;
 select * into mr from match_rounds where match_id=m.id and round_number=r.current_round;
 if exists(select 1 from submissions where round_id=mr.id and user_id=auth.uid()) then raise exception 'Answer already submitted'; end if;
 select * into c from challenges where id=mr.challenge_id;
 ok:=lower(trim(p_answer))=lower(trim(c.answer));
 if ok then pts:=100; end if;
 insert into submissions(round_id,user_id,answer,correct,points) values(mr.id,auth.uid(),left(p_answer,200),ok,pts);
 update player_match_stats set points=points+pts,correct_answers=correct_answers+(case when ok then 1 else 0 end) where match_id=m.id and user_id=auth.uid();
 select count(*) into done from submissions where round_id=mr.id; select count(*) into total from room_players where room_id=p_room;
 return jsonb_build_object('correct',ok,'points',pts,'submitted',done,'players',total);
end $$;

create or replace function public.advance_room_round(p_room uuid)
returns jsonb language plpgsql security definer set search_path=public as $$
declare r public.rooms; m public.matches; mr public.match_rounds; c uuid; j jsonb;
begin
 select * into r from rooms where id=p_room for update;
 if not found or r.host_id<>auth.uid() then raise exception 'Only host can advance'; end if;
 if r.status<>'playing' then raise exception 'No active round'; end if;
 select * into m from matches where room_id=p_room and status='playing' order by started_at desc limit 1;
 select * into mr from match_rounds where match_id=m.id and round_number=r.current_round;
 if now()<mr.deadline_at and (select count(*) from submissions where round_id=mr.id)<(select count(*) from room_players where room_id=p_room) then raise exception 'Wait for all players or the round deadline'; end if;
 update match_rounds set completed_at=now() where id=mr.id;
 if r.current_round>=r.rounds_total then
  update matches set status='completed',completed_at=now() where id=m.id; update rooms set status='completed' where id=p_room;
  update profiles p set games_played=games_played+1,total_xp=total_xp+coalesce(s.points,0) from player_match_stats s where s.match_id=m.id and p.id=s.user_id;
  select jsonb_build_object('completed',true,'scores',(select jsonb_agg(jsonb_build_object('user_id',s.user_id,'username',p.username,'points',s.points,'correct',s.correct_answers) order by s.points desc) from player_match_stats s join profiles p on p.id=s.user_id where s.match_id=m.id)) into j;
  return j;
 end if;
 select challenge_id into c from match_rounds where match_id=m.id and round_number=r.current_round+1;
 update match_rounds set deadline_at=now()+interval '90 seconds' where match_id=m.id and round_number=r.current_round+1;
 update rooms set current_round=current_round+1,current_challenge_id=c,round_deadline=now()+interval '90 seconds' where id=p_room;
 return jsonb_build_object('completed',false,'round',r.current_round+1);
end $$;

create or replace function public.leave_room(p_room uuid)
returns void language plpgsql security definer set search_path=public as $$
declare r public.rooms;
begin
 select * into r from rooms where id=p_room;
 if not found or not public.is_room_member(p_room) then return; end if;
 if r.status in ('waiting','ready') then delete from room_players where room_id=p_room and user_id=auth.uid(); if r.host_id=auth.uid() then update rooms set status='cancelled' where id=p_room; end if;
 else update room_players set connected=false where room_id=p_room and user_id=auth.uid(); end if;
end $$;

create or replace function public.get_daily_challenge()
returns jsonb language plpgsql security definer set search_path=public as $$
declare d date:=(now() at time zone 'UTC')::date; dc public.daily_challenges; c public.challenges;
begin
 select * into dc from daily_challenges where challenge_date=d;
 if not found then select * into c from challenges where mode='daily' and active order by random() limit 1; if not found then raise exception 'Daily challenge unavailable'; end if; insert into daily_challenges(challenge_date,challenge_id) values(d,c.id) on conflict do nothing; select * into dc from daily_challenges where challenge_date=d; end if;
 select * into c from challenges where id=dc.challenge_id;
 return jsonb_build_object('date',d,'category',c.category,'difficulty',c.difficulty,'prompt',c.prompt,'options',c.options);
end $$;
create or replace function public.submit_daily_answer(p_answer text)
returns jsonb language plpgsql security definer set search_path=public as $$
declare d date:=(now() at time zone 'UTC')::date; dc public.daily_challenges; c public.challenges; ok boolean; pts int:=0;
begin
 if auth.uid() is null then raise exception 'Sign in first'; end if; perform get_daily_challenge(); select * into dc from daily_challenges where challenge_date=d;
 if exists(select 1 from daily_attempts where challenge_date=d and user_id=auth.uid()) then raise exception 'Already completed today'; end if;
 select * into c from challenges where id=dc.challenge_id; ok:=lower(trim(p_answer))=lower(trim(c.answer)); if ok then pts:=100; end if;
 insert into daily_attempts(challenge_date,user_id,answer,correct,points) values(d,auth.uid(),left(p_answer,200),ok,pts); update profiles set total_xp=total_xp+pts where id=auth.uid();
 return jsonb_build_object('correct',ok,'points',pts,'explanation',c.explanation);
end $$;

grant execute on function public.save_my_profile(text,text),public.create_room(text,int,int),public.join_room(text),public.set_room_ready(uuid,boolean),public.get_room_lobby(uuid),public.start_match(uuid),public.get_room_challenge(uuid),public.submit_room_answer(uuid,text),public.advance_room_round(uuid),public.leave_room(uuid),public.get_daily_challenge(),public.submit_daily_answer(text) to authenticated;
-- Enable Realtime replication for lobby changes.
do $$ begin alter publication supabase_realtime add table public.rooms; exception when duplicate_object then null; when undefined_object then null; end $$;
do $$ begin alter publication supabase_realtime add table public.room_players; exception when duplicate_object then null; when undefined_object then null; end $$;

insert into public.challenges(mode,category,difficulty,prompt,options,answer,explanation,clue_map) values
('duel','Pattern Logic','easy','What number comes next? 2, 4, 8, 16, …','["18","24","32","36"]','32','Each number doubles.','{}'),
('duel','Word Logic','easy','Which word does not belong?','["Triangle","Square","Circle","Blue"]','Blue','The first three are shapes; blue is a colour.','{}'),
('duel','Number Logic','medium','What is 15% of 200?','["20","25","30","35"]','30','0.15 × 200 = 30.','{}'),
('duel','Reasoning','medium','If all Zips are Zaps and all Zaps are Zops, are all Zips Zops?','["Yes","No","Cannot tell"]','Yes','The relationship is transitive.','{}'),
('duel','Pattern Logic','hard','What comes next? 1, 1, 2, 3, 5, 8, …','["11","12","13","15"]','13','Each term is the sum of the previous two.','{}'),
('duel','General Logic','easy','A clock shows 3:00. What is the angle between its hands?','["45°","60°","90°","180°"]','90°','At three o’clock the hands are perpendicular.','{}'),
('together','Code Breaker','easy','TEAM MISSION: What is missing? 3, 6, 9, __, 15','["10","11","12","13"]','12','The sequence increases by three.','{"1":"Identify the step between numbers.","2":"Compare the differences in the sequence."}'),
('together','Shared Reasoning','medium','TEAM MISSION: A farmer has 12 sheep. All but 5 wander away. How many remain?','["5","7","12","0"]','5','All but five means five remain.','{"1":"Focus on the words all but.","2":"Read the question carefully before calculating."}'),
('together','Pattern Logic','hard','TEAM MISSION: Find the next number: 1, 4, 9, 16, 25, __','["30","32","36","49"]','36','These are square numbers.','{"1":"Look at the differences.","2":"Try expressing each number as a square."}'),
('together','Word Logic','easy','TEAM MISSION: Rearrange the letters LISTEN to make a word meaning quiet.','["SILENT","ENLIST","TINSEL","INLETS"]','SILENT','LISTEN and SILENT use the same letters.','{"1":"Think of a word that describes quiet.","2":"All six letters are used exactly once."}'),
('together','Deduction','medium','TEAM MISSION: Ava is older than Ben. Ben is older than Cara. Who is youngest?','["Ava","Ben","Cara","Cannot tell"]','Cara','The order is Ava, Ben, then Cara.','{"1":"Compare Ava with Ben.","2":"Compare Ben with Cara."}'),
('mystery','Case File','easy','MYSTERY: Wet footprints lead to a window locked from inside. What should investigators establish first?','["When the footprints appeared","Whether ghosts exist","The colour of the walls","The weather next week"]','When the footprints appeared','Establish the timeline before assuming an impossible event.','{"1":"You know the window is locked now, not when the footprints appeared.","2":"Focus on the sequence of events."}'),
('mystery','Timeline','medium','MYSTERY: A book was last seen at 5 pm and found missing at 7 pm. What time window should investigators check first?','["Before 5 pm","5 pm to 7 pm","After 7 pm","Midnight only"]','5 pm to 7 pm','The disappearance occurred between the last confirmed sighting and discovery.','{"1":"Separate last sighting from discovery.","2":"The answer lies between two known events."}'),
('mystery','Evidence','easy','MYSTERY: Three people were in a room. One says the lights went out before the clock stopped. What should be checked first?','["Whether the clock needs power","The colour of the curtains","Tomorrow’s weather","The room number"]','Whether the clock needs power','Check a practical explanation before drawing conclusions.','{"1":"Think about what can make a clock stop.","2":"Look for a connection between electricity and the clock."}'),
('mystery','Deduction','medium','MYSTERY: A key is found beside a locked cabinet. Which fact would be most useful next?','["Whether the key fits the cabinet","Who painted the room","The day of the week","The cabinet colour"]','Whether the key fits the cabinet','Test whether the key is relevant to the locked cabinet.','{"1":"The key may or may not belong to the cabinet.","2":"Identify the direct test of the key."}'),
('mystery','Sequence','hard','MYSTERY: A note says the meeting happened after the alarm but before sunset. Which detail would narrow the timeline most?','["The alarm time","The colour of the note","The size of the room","The writer’s favourite food"]','The alarm time','A known time anchor helps narrow the sequence.','{"1":"Find the event that provides a time anchor.","2":"Ignore details unrelated to time."}'),
('daily','Daily Logic','easy','DAILY: What has keys but cannot open a lock?','["A map","A piano","A river","A clock"]','A piano','A piano has musical keys.','{}'),
('daily','Daily Pattern','medium','DAILY: What is the next number? 5, 10, 20, 40, …','["45","60","70","80"]','80','Each number doubles.','{}'),
('daily','Daily Reasoning','hard','DAILY: If yesterday was two days before Friday, what day is today?','["Tuesday","Wednesday","Thursday","Friday"]','Thursday','Two days before Friday is Wednesday, so today is Thursday.','{}');
