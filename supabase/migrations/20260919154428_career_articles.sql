-- Career content is served through the backend; browsers have no direct table access.
create table if not exists public.career_articles (
  id uuid primary key default gen_random_uuid(),
  slug text not null unique check (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$' and length(slug) <= 100),
  title text not null check (length(title) between 1 and 180),
  excerpt text not null check (length(excerpt) between 1 and 320),
  body text not null check (length(body) between 1 and 50000),
  category text not null check (length(category) between 1 and 60),
  author text not null default 'Asimos redaksiyası',
  cover_url text not null default '',
  cover_style text not null default 'mint' check (cover_style in ('mint', 'peach', 'blue', 'lilac')),
  reading_minutes integer not null default 1 check (reading_minutes > 0),
  featured boolean not null default false,
  status text not null default 'draft' check (status in ('draft', 'published')),
  published_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint published_article_has_date check (status <> 'published' or published_at is not null)
);
alter table public.career_articles enable row level security;
revoke all on public.career_articles from public, anon, authenticated;
grant select, insert, update, delete on public.career_articles to service_role;
create index if not exists career_articles_public_idx on public.career_articles (featured desc, published_at desc, id) where status = 'published';
create index if not exists career_articles_admin_idx on public.career_articles (featured desc, updated_at desc, id);

-- Initial editorial content; all articles remain editable in the admin panel.
insert into public.career_articles (slug,title,excerpt,body,category,cover_style,reading_minutes,featured,status,published_at) values ('musahibeye-nece-hazirlasmali','Müsahibəyə necə hazırlaşmalı?','İlk təəssüratdan son suala qədər: özünüzü daha aydın ifadə etmək və müsahibəyə inamla getmək üçün praktik addımlar.','Müsahibə yalnız suallara cavab vermək deyil. Bu, həm sizin təcrübənizi göstərmək, həm də işin sizə uyğun olub-olmadığını anlamaq üçün bir görüşdür. Hazırlıq həyəcanı tam aradan qaldırmasa da, diqqətinizi əsas məqamlara yönəltməyə kömək edir.

## 1. Şirkəti və vakansiyanı araşdırın

Elanı yenidən oxuyun və əsas vəzifələri ayrıca qeyd edin. Şirkətin fəaliyyətini, məhsulunu və müştərilərini öyrənin. Elanın tələb etdiyi bacarıqlarla öz təcrübənizin kəsişdiyi üç məqamı seçin. Hər biri üçün konkret nümunə hazırlayın.

## 2. Özünüz haqqında qısa təqdimat hazırlayın

“Özünüz haqqında danışın” sualına cavabınız bütün həyat hekayəniz olmamalıdır. Hazırda nə etdiyinizi, hansı təcrübənizin bu rola uyğun olduğunu və niyə həmin işi istədiyinizi bir-iki dəqiqədə izah edin. Təcrübəniz azdırsa, təhsil layihələrini, könüllülüyü və öyrəndiyiniz bacarıqları misal göstərin.

## 3. Cavablarınızı nümunələrlə gücləndirin

“Məsuliyyətliyəm” demək əvəzinə, məsuliyyət götürdüyünüz bir vəziyyəti danışın. Hadisəni, üzərinizə düşən işi, atdığınız addımı və nəticəni ardıcıllıqla izah edin. Komanda nailiyyətindən danışarkən öz töhfənizi dəqiqləşdirin. Xatırlamadığınız rəqəmləri uydurmayın.

- Çətin bir problemi necə həll etdiyinizi düşünün.
- Yeni bir bacarığı necə öyrəndiyinizə nümunə hazırlayın.
- Komanda ilə fikir ayrılığını necə idarə etdiyinizi izah edin.

## 4. Öz suallarınızı hazırlayın

Görüşün sonunda sual vermək rolun gündəlik işini anlamağa kömək edir. İlk aylarda sizdən hansı nəticələrin gözlənildiyini, komandanın necə işlədiyini və növbəti seçim mərhələsinin nə olduğunu soruşa bilərsiniz. Cavabı elanda açıq yazılmış sualları təkrarlamaq əvəzinə, sizin qərarınıza təsir edən mövzuları seçin.

## 5. Görüşün texniki tərəfini yoxlayın

Üzbəüz görüş üçün ünvanı və yol vaxtını əvvəlcədən yoxlayın. Onlayn görüşdə kamera, mikrofon və internet bağlantısını sınayın. CV-nizin bir nüsxəsini və qeydlərinizi əl altında saxlayın. Sakit məkan seçin və bildirişləri müvəqqəti söndürün.

> Məqsəd əzbərlənmiş ideal cavab vermək deyil. Məqsəd bildiyinizi, etdiyinizi və öyrənməyə hazır olduğunuzu aydın göstərməkdir.

## 6. Görüşdən sonra qeydlər aparın

Hansı suallarda çətinlik çəkdiyinizi, rol haqqında nə öyrəndiyinizi və sizə deyilən növbəti addımları yazın. Uyğun əlaqə kanalı varsa, qısa təşəkkür mesajı göndərə bilərsiniz. Nəticə necə olursa olsun, qeydləriniz növbəti müsahibəyə daha yaxşı hazırlaşmağınıza kömək edəcək.','Müsahibə','mint',2,true,'published',now()) on conflict (slug) do nothing;
insert into public.career_articles (slug,title,excerpt,body,category,cover_style,reading_minutes,featured,status,published_at) values ('cv-nizi-ferqlendiren-5-meslehet','CV-nizi fərqləndirən 5 məsləhət','Təcrübənizi sadalamaqdan daha artığını edin. Bacarıqlarınızı və nəticələrinizi aydın göstərən CV üçün beş sadə yanaşma.','Yaxşı CV oxucunun əsas sualına tez cavab verir: bu namizəd həmin işi görə bilərmi? Sənədinizin məqsədi hər detalı yerləşdirmək yox, vakansiyaya uyğun təcrübənizi görünən etməkdir.

## 1. Hər vakansiyaya uyğunlaşdırın

Eyni CV-ni hər yerə göndərməzdən əvvəl elandakı əsas tələbləri oxuyun. Həqiqətən sahib olduğunuz uyğun bacarıqları və layihələri önə çəkin. Başlıq və qısa təqdimat hissəsində hansı sahədə işləmək istədiyinizi aydın yazın. Elanın mətnini olduğu kimi köçürməyin.

## 2. Vəzifə ilə yanaşı nəticəni göstərin

“Satışla məşğul olmuşam” ümumi məlumatdır. Hansı məhsulu kimə təqdim etdiyinizi, prosesdə nəyi yaxşılaşdırdığınızı və nəticəni necə ölçdüyünüzü qeyd etmək daha faydalıdır. Dəqiq rəqəminiz yoxdursa, gördüyünüz işin miqyasını və konkret töhfənizi sözlə təsvir edin.

- İşin və ya layihənin qısa kontekstini göstərin.
- Öz məsuliyyətinizi və etdiyiniz işi dəqiqləşdirin.
- Yalnız əsaslandıra bildiyiniz nəticələri yazın.

## 3. Oxunaqlı quruluş seçin

Əlaqə məlumatları, təcrübə, təhsil və bacarıqlar üçün aydın başlıqlar istifadə edin. Tarixləri eyni formatda yazın və son təcrübəni əvvəl göstərin. Çox kiçik şrift, uzun abzaslar və həddindən artıq dekorasiya oxumağı çətinləşdirə bilər. Mətnin seçilə və kopyalana bildiyi PDF faylı hazırlamaq praktik seçimdir; elanda başqa format istənilibsə, həmin tələbi izləyin.

## 4. Təcrübəniz azdırsa, layihələrinizi göstərin

İlk işinizi axtarırsınızsa, təcrübə bölməsini boş saxlamaq məcburiyyətində deyilsiniz. Təhsil layihəsi, könüllü fəaliyyət və ya şəxsi işiniz bacarıqlarınızı göstərə bilər. Layihənin məqsədini, istifadə etdiyiniz alətləri və sizin rolunuzu qısa izah edin. Portfolio keçidinizin açıldığını yoxlayın.

## 5. Göndərməzdən əvvəl son yoxlama edin

Telefon və e-poçt ünvanınızın doğru olduğuna əmin olun. Orfoqrafiyanı, tarixləri və keçidləri yoxlayın. Fayla aydın ad verin, məsələn “Ad_Soyad_CV.pdf”. Sənədi başqa cihazda açaraq düzülüşünü də yoxlayın. Mümkünsə, bir tanışınızdan ilk oxunuşda nəyin aydın olmadığını soruşun.

> Güclü CV daha çox söz deyil, daha uyğun və daha konkret məlumat deməkdir.

CV-ni göndərdikdən sonra müraciət etdiyiniz vakansiyanın adını və tarixini qeyd edin. Belə bir siyahı sonrakı əlaqəni və müsahibəyə hazırlığı asanlaşdırır.','CV','peach',2,true,'published',now()) on conflict (slug) do nothing;
insert into public.career_articles (slug,title,excerpt,body,category,cover_style,reading_minutes,featured,status,published_at) values ('uzaqdan-isleyerken-mehsuldarligi-artirin','Uzaqdan işləyərkən məhsuldarlığı artırın','Diqqətinizi qoruyun, iş gününüzə sərhəd qoyun və komanda ilə əlaqəni saxlayın. Evdən iş üçün tətbiq edə biləcəyiniz vərdişlər.','Uzaqdan işləmək yol vaxtına qənaət edə bilər, amma ev və iş arasındakı sərhədi də zəiflədə bilər. Məhsuldar olmaq üçün bütün günü məşğul görünmək lazım deyil. Əsas məsələ prioritetləri bilmək və işi davamlı şəkildə təşkil etməkdir.

## Günün əsas nəticəsini müəyyənləşdirin

İşə başlamazdan əvvəl günün sonunda tamamlanmasını istədiyiniz bir-üç nəticəni yazın. Uzun tapşırıq siyahısını kiçik, konkret addımlara bölün. “Layihə üzərində işləmək” əvəzinə “Təklifin ilkin mətnini hazırlamaq” kimi ölçülə bilən bir addım seçin.

## Diqqət üçün vaxt ayırın

Çətin işi daha enerjili olduğunuz saatlara salmağa çalışın. Təqvimdə diqqətli iş üçün zaman ayırın və həmin vaxt ərzində lazım olmayan bildirişləri bağlayın. İşiniz sürətli cavab tələb edirsə, əlçatan olmayacağınız müddəti komandanızla əvvəlcədən razılaşdırın.

- Bir anda bir əsas tapşırıqla işləyin.
- Mesajları yoxlamaq üçün uyğun aralıqlar seçin.
- Yarımçıq işə qayıtmaq üçün növbəti addımı qeyd edin.

## İş yerinizi sadələşdirin

Ayrıca otağınız olmasa da, iş üçün sabit bir yer seçmək faydalıdır. Lazım olan əşyaları yaxın saxlayın və diqqətinizi yayındıran şeyləri azaltmağa çalışın. Ekranın yerləşməsi və oturuşunuz rahat olmalıdır. Fasilələrdə yerinizdən qalxın və hərəkət edin.

## Komanda ilə aydın ünsiyyət qurun

Qısa yazılı yeniləmədə nəyi tamamladığınızı, növbəti işinizi və maneələri bildirin. Bir tapşırıq verərkən gözlənilən nəticəni, məsul şəxsi və razılaşdırılmış vaxtı dəqiqləşdirin. Mətnlə uzanan anlaşılmazlığı qısa görüşlə həll etmək daha səmərəli ola bilər.

## İş gününü bağlama vərdişi yaradın

Günün sonunda görülən işləri nəzərdən keçirin və sabahın ilk addımını yazın. Sonra iş proqramlarını bağlayın. İş saatlarından kənar əlçatanlıq gözləntilərini rəhbərinizlə razılaşdırmaq şəxsi vaxtınızı planlaşdırmağa kömək edir.

> Davamlı məhsuldarlıq hər dəqiqəni işlə doldurmaqdan deyil, diqqət, ünsiyyət və istirahət arasında uyğun ritm tapmaqdan yaranır.

Bir həftə ərzində yalnız bir yeni vərdişi sınayın. İşinizə real kömək edənləri saxlayın, uyğun gəlməyənləri dəyişin. Hər komandanın və hər insanın iş ritmi fərqlidir.','Uzaqdan iş','blue',2,true,'published',now()) on conflict (slug) do nothing;
