author: Hugo Flores
summary: Guía de bastionamiento de Debian 13
id: 1
categories: codelab,markdown
environments: Web
status: Published
feedback link: Un enlace en el que los usuarios puedan darte feedback (quizás creando un issue en un repositorio de git)
analytics account: ID de Google Analytics
# Proyecto 3 Hacking Ético (TalentScout)
---

## Parte 1
a) Ejemplo de combinación para la inyección SQL
  Escribo los valores

   - username: a" UNION SELECT 1, "1234" --
   - password: 1234

   ![img1](img/img1.png)

  En el campo

   - username y password

  Del formulario de la página

   - http://talentscout.local/list_players.php (que incluye el formulario de inicio de sesión de auth.php)

    ![img2](img/img2.png)

  La consulta SQL que se ejecuta es

   - SELECT userId, password FROM users WHERE username = "a" UNION SELECT 1, "mypass" -- "

  Campos del formulario web utilizados en la consulta SQL

   - username

  Campos del formulario web no utilizados en la consulta SQL

   - password (el valor de la contraseña no se utiliza en la consulta, pero se utiliza en el código PHP para compararlo con el resultado de la consulta)  

b)
Gracias a la SQL Injection del apartado anterior, sabemos que este formulario es vulnerable y conocemos el nombre de los campos de la tabla “users”. Para tratar de impersonar a un usuario, nos hemos descargado un diccionario que contiene algunas de las contraseñas más utilizadas (se listan a continuación):
password
123456
12345678
1234
qwerty
12345678
dragon
Dad un ataque que, utilizando este diccionario, nos permita impersonar un usuario de esta aplicación y acceder en nombre suyo. Tened en cuenta que no sabéis ni cuántos usuarios hay registrados en la aplicación, ni los nombres de estos.

Informe de Ataque de Diccionario

Explicación del ataque
El ataque consiste en repetir el proceso de login, una vez por cada usuario de la aplicación, utilizando en cada interacción una contraseña diferente del diccionario. Para obtener los nombres de usuario, se ha aprovechado una vulnerabilidad de inyección SQL en la página insert_player.php para volcar la tabla de usuarios.

Campo de usuario con el que el ataque ha tenido éxito

luis

Campo de contraseña con que el ataque ha tenido éxito

1234  



---

## Caso 2: Derechos de Propiedad Industrial (Patentes)

El Caso DABUS: La IA como Inventor Patentable
Este caso ejemplifica el reto de la Propiedad Industrial, específicamente en el ámbito de las Patentes, donde se exige que el inventor sea un humano para que la invención sea legalmente protegible. La Propiedad Industrial protege invenciones (patentes), marcas, diseños industriales e indicaciones geográficas.
A. Descripción y Hechos del Caso
El proyecto DABUS (Device for the Autonomous Bootstrapping of Unified Sentience) es un sistema de IA creado por Stephen Thaler, cuyo objetivo es emular funciones cerebrales con propósitos creativos, generando invenciones de forma autónoma, es decir, sin intervención humana directa.
El equipo de Thaler presentó solicitudes de patentes en más de 150 países para proteger dos invenciones generadas por DABUS, con la solicitud explícita de nombrar al sistema de IA como el inventor.
B. Repercusión y Decisión Legal (Patentes)
La mayoría de las oficinas de propiedad industrial, que se ocupan exclusivamente de la Propiedad Industrial (como la OEPM en España), denegaron las solicitudes de patente bajo la base de la falta de un inventor humano:
1. Estados Unidos y Unión Europea (Oficina Europea de Patentes, EPO): Tanto la USPTO como la EPO denegaron las solicitudes. Las normativas de patentes exigen que el inventor sea una persona física. En la UE, el inventor debe ser una persona física. El equipo de Thaler incluso intentó declarar que el solicitante (una persona física) tenía derechos por ser el propietario de la máquina, pero esto fue igualmente rechazado.
2. Sudáfrica: Sudáfrica se convirtió en el único país que concedió una patente a una invención de DABUS. Esto se debió a que su legislación no prevé expresamente que solo las personas físicas puedan ser inventoras, permitiendo que la solicitud avanzara con un análisis de forma, pero no necesariamente de fondo.
Repercusión en la Propiedad Industrial: Este caso subraya que, aunque la IA pueda generar innovaciones técnicamente "nuevas", el sistema legal de patentes, que protege invenciones consistentes en productos y procedimientos susceptibles de utilización con fines industriales, mantiene una visión antropocéntrica. Las patentes son derechos territoriales y duran típicamente 20 años desde la solicitud, siendo la protección constitutiva (obligatoria). El rechazo de las patentes de DABUS ilustra cómo el sistema busca un equilibrio entre el incentivo a la innovación y el requisito de la autoría humana, enfrentándose al dilema de si invertir millones de euros en IA se justificará si los resultados caen en el dominio público.


---

## Resultado de justicio.es

### Caso 1
Prompt: Si uso una obra protegida con una IA generativa, que derechos de creación artísticas infringiría

Resultado:

Al emplear una obra protegida en el desarrollo o entrenamiento de una IA generativa, se pueden vulnerar varios derechos de los autores o titulares de la obra, conforme a la legislación de propiedad intelectual y la normativa europea. A continuación, se detallan los aspectos más relevantes:

Derechos de autor: Según la DIRECTIVA 96/9/CE, las bases de datos que constituyan una creación intelectual de su autor están protegidas por derechos de autor. Esto implica que el uso de obras protegidas para entrenar una IA generativa podría considerarse una infracción si no se cuenta con la autorización del titular de los derechos [1].

Derechos afines: La DIRECTIVA 93/83/CEE establece que la protección de los derechos afines de autor no afecta a los derechos de autor, lo que significa que, además de los derechos de autor, también se deben considerar los derechos relacionados que puedan existir sobre la obra utilizada [2].

Medidas tecnológicas: La DIRECTIVA 2001/29/CE menciona que las medidas tecnológicas adoptadas por los titulares de derechos disfrutarán de protección jurídica. Si la IA generativa elude estas medidas sin autorización, podría estar cometiendo una infracción [3].

Información para la gestión de derechos: La misma DIRECTIVA 2001/29/CE establece que se debe proteger la información para la gestión de derechos. Esto incluye cualquier acto de supresión o alteración de esta información, lo que podría ser relevante si la IA utiliza obras sin respetar esta información [3].

Excepciones y limitaciones: Aunque existen ciertas excepciones y limitaciones al derecho de reproducción, como se establece en el artículo 5 de la DIRECTIVA 2001/29/CE, estas son específicas y no deben afectar la explotación normal de la obra. Por lo tanto, si el uso de la obra por parte de la IA no se ajusta a estas excepciones, se consideraría una violación de los derechos de autor [3].

Acuerdo de Asociación: En el contexto de un acuerdo de asociación, se establece la obligación de proteger adecuadamente los derechos de autor y afines, lo que implica que cualquier uso no autorizado de obras protegidas podría ser considerado una infracción [4].

Ejemplo práctico:
Si una empresa desarrolla una IA generativa que utiliza obras literarias protegidas sin el consentimiento de los autores, podría estar violando los derechos de autor conforme a la normativa europea. Esto incluye no solo la reproducción de fragmentos de texto, sino también la creación de nuevas obras derivadas basadas en el contenido original, lo que podría llevar a reclamaciones legales por parte de los titulares de derechos.

 Jurisprudencia Menor 
La jurisprudencia relevante en relación con el uso de obras protegidas en el desarrollo o entrenamiento de una IA generativa se encuentra principalmente en la Sentencia del Tribunal de Justicia de la Unión Europea (TJUE) en el asunto CV-ONLINE LATVIA SIA C-762/19. Esta sentencia establece que el derecho sui generis de los fabricantes de bases de datos, conforme al artículo 7 de la Directiva 96/9/CE, permite a estos prohibir la extracción y/o reutilización de la totalidad o de una parte sustancial del contenido de la base de datos, siempre que dicha extracción represente una inversión sustancial desde el punto de vista cuantitativo o cualitativo. Esta protección tiene como objetivo garantizar que quienes asumen el riesgo de inversión en la creación de bases de datos puedan amortizar dicha inversión, evitando la apropiación no autorizada de los resultados obtenidos [5] [2002] [2003]. Además, se destaca que los actos que excedan los derechos legítimos del usuario y que perjudiquen la inversión del fabricante pueden dar lugar a acciones legales, lo que implica que el uso de obras protegidas en IA generativa sin autorización podría vulnerar estos derechos [2006]. Por tanto, el desarrollo de IA generativa que utilice obras protegidas debe considerar la normativa de propiedad intelectual y la posible infracción de los derechos de los autores o titulares de las obras, así como la normativa europea que protege las bases de datos y su contenido.

 Conclusión 
El uso de obras protegidas para entrenar una IA generativa sin autorización puede infringir los derechos de autor y otros derechos de propiedad intelectual. Esto incluye tanto la reproducción de la obra como la creación de obras derivadas no autorizadas.


Los elementos clave son: la necesidad de obtener autorización de los titulares de derechos para usar sus obras en el entrenamiento de la IA y el respeto a las medidas tecnológicas de protección y la información de gestión de derechos. La jurisprudencia del TJUE también protege a los fabricantes de bases de datos, impidiendo la extracción no autorizada de su contenido.


En la práctica, esto significa que las empresas que desarrollan IA generativas deben asegurarse de obtener las licencias necesarias para utilizar obras protegidas, respetar las excepciones y limitaciones al derecho de reproducción, y evitar eludir las medidas tecnológicas de protección. No hacerlo puede acarrear reclamaciones legales por parte de los titulares de los derechos.

### Caso 2

Prompt: Como sería el tema legal con IA generativa en el tema de Derechos de Propiedad Industrial

Respuesta:

La legislación europea y española aborda el uso de la inteligencia artificial generativa en el ámbito de los derechos de propiedad industrial a través de varias directivas y reglamentos que regulan patentes, marcas y diseños industriales.

Patentes: La protección de las invenciones, incluidas aquellas generadas por inteligencia artificial, se encuentra regulada en la legislación de patentes de la Unión Europea. Las patentes protegen las invenciones que son nuevas, implican una actividad inventiva y son susceptibles de aplicación industrial. Sin embargo, la legislación no especifica de manera directa cómo se aplican estas normas a las invenciones generadas por inteligencia artificial. Esto puede generar incertidumbre respecto a si una invención creada por un sistema de IA puede ser patentada y quién sería el titular de la patente: el creador del algoritmo, el usuario de la IA o la propia IA.

Marcas: Las marcas están protegidas bajo la legislación de propiedad industrial, que incluye la Directiva 2015/2436 de la UE. Esta legislación establece que las marcas deben ser distintivas y no pueden ser confundidas con otras marcas registradas. En el contexto de la inteligencia artificial, se plantea la cuestión de si una marca generada o sugerida por un sistema de IA puede ser registrada y si cumple con los requisitos de distintividad y no confusión.

Diseños industriales: La protección de los diseños industriales se regula a través del Reglamento (CE) No 6/2002 del Consejo de la UE. Este reglamento protege los diseños que son nuevos y tienen carácter singular. En el caso de los diseños generados por inteligencia artificial, la cuestión de la titularidad y la originalidad se vuelve relevante, ya que la legislación actual no aborda explícitamente cómo se aplican estas normas a los diseños creados por sistemas automatizados.

Protección contra la competencia desleal: La legislación también incluye la protección contra la competencia desleal, que se define en el artículo 10 bis del Convenio de París para la Protección de la Propiedad Industrial. Esta protección puede ser relevante en el contexto de la inteligencia artificial generativa, especialmente si se considera que la IA puede crear productos que imiten o se asemejen a los de otros, lo que podría dar lugar a conflictos de interés y disputas legales.

Derechos de autor: Aunque no se menciona específicamente la inteligencia artificial generativa, la Directiva 96/9/CE del Parlamento Europeo y del Consejo establece que las bases de datos que constituyan una creación intelectual están protegidas por derechos de autor, lo que podría extenderse a las obras generadas por IA en función de su originalidad y creatividad. La protección del derecho de autor no se extiende al contenido de las bases de datos, lo que significa que el contenido generado por IA podría no estar protegido si no cumple con los criterios de originalidad [1].

Acuerdos internacionales: En el ámbito de los acuerdos internacionales, como el Acuerdo de Asociación y el Acuerdo Euromediterráneo, se menciona que la propiedad intelectual incluye derechos de autor, patentes, diseños industriales y protección contra la competencia desleal, lo que refuerza la importancia de la propiedad intelectual en el contexto de la innovación y la tecnología [2][3].

Ejemplo práctico: Si una empresa utiliza un sistema de inteligencia artificial para diseñar un nuevo producto, la empresa debe considerar si el diseño puede ser patentado, si puede registrar una marca asociada y si el diseño cumple con los requisitos de originalidad para la protección de derechos de autor. Además, debe asegurarse de que el uso de la IA no infrinja los derechos de propiedad industrial de terceros, lo que podría dar lugar a litigios por competencia desleal.

En resumen, la regulación del uso de la inteligencia artificial generativa en el ámbito de los derechos de propiedad industrial es compleja y presenta desafíos en cuanto a la titularidad, la originalidad y la protección efectiva de las innovaciones generadas por estas tecnologías.

🇪🇸  Legislación Estatal 
La legislación española y europea aborda el uso de la inteligencia artificial generativa en el ámbito de los Derechos de Propiedad industrial, incluyendo patentes, marcas y diseños industriales, a través de diversas normativas que regulan estos derechos. A continuación, se analizan las principales leyes relevantes en este contexto:

1. Ley 24/2015, de 24 de julio, de Patentes
La Ley de Patentes establece que el derecho a la patente pertenece al inventor o a sus causahabientes, y es transmisible por todos los medios que el derecho reconoce [5]. Esto implica que las invenciones generadas por inteligencia artificial pueden ser patentadas si cumplen con los requisitos de novedad y actividad inventiva. La ley también menciona que si varias personas realizan la misma invención de forma independiente, el derecho a la patente pertenecerá a aquella cuya solicitud tenga una fecha anterior [5]. Esto es crucial en el contexto de la inteligencia artificial, donde múltiples desarrolladores pueden generar soluciones similares simultáneamente.

2. Ley 20/2003, de 7 de julio, de Protección Jurídica del Diseño Industrial
Esta ley regula la protección de los diseños industriales, estableciendo que el diseño debe ser nuevo y singular para ser registrado [6]. La ley permite la protección de diseños generados por inteligencia artificial siempre que cumplan con estos criterios. Además, se contempla la posibilidad de que un diseño no registrado goce de protección comunitaria específica frente a actos de explotación no autorizada durante un período determinado [6].

3. Reglamento (CE) n.º 6/2002 sobre los dibujos y modelos comunitarios
Este reglamento establece un marco para la protección de los diseños en toda la Unión Europea, permitiendo que los diseños generados por inteligencia artificial puedan ser protegidos a nivel comunitario si cumplen con los requisitos establecidos [6]. La legislación europea busca armonizar la protección de los diseños y facilitar su inscripción en todos los Estados miembros.

4. Organización Europea de Patentes
El Convenio sobre la Patente Europea establece que la patente europea confiere a su titular los mismos derechos que una patente nacional en los Estados contratantes [7]. Esto significa que, si una invención generada por inteligencia artificial es patentada en un país, puede ser válida en otros países europeos, facilitando su protección en un mercado más amplio.

5. Relación con los derechos de autor
El Acuerdo Comercial entre la Unión Europea y sus Estados Miembros y otros acuerdos internacionales también tocan la relación entre los derechos de diseño y los derechos de autor, permitiendo que un diseño pueda ser protegido bajo ambas legislaciones si cumple con las condiciones pertinentes [7]. Esto es relevante para las creaciones generadas por inteligencia artificial que pueden tener elementos que se superponen entre el diseño industrial y la propiedad intelectual.

Conclusiones sobre la Inteligencia Artificial Generativa
La legislación actual proporciona un marco para la protección de invenciones y diseños generados por inteligencia artificial, siempre que cumplan con los requisitos de novedad y singularidad. Sin embargo, el tratamiento específico de los derechos de propiedad industrial en relación con la inteligencia artificial todavía está evolucionando, y es posible que se requieran futuras modificaciones legislativas para abordar de manera más directa los desafíos y oportunidades que presenta esta tecnología emergente.

 Jurisprudencia Menor 
La regulación de la inteligencia artificial generativa en el ámbito de los Derechos de Propiedad Industrial, como patentes, marcas y diseños industriales, se ve influenciada por la jurisprudencia del Tribunal de Justicia de la Unión Europea (TJUE). En particular, la Sentencia CV-ONLINE LATVIA SIA C-762/19 establece que la protección de bases de datos bajo el derecho sui generis, según la Directiva 96/9, asegura que la inversión sustancial en la creación y mantenimiento de bases de datos no sea objeto de extracción o reutilización no autorizada, lo que es relevante en contextos donde la inteligencia artificial maneja grandes volúmenes de datos [8] [2002] [2003]. Esta protección es crucial para fomentar la innovación y el desarrollo en el sector de la información, permitiendo que los fabricantes de bases de datos controlen el uso de su contenido y protejan su inversión. Además, la Directiva 2004/48 establece medidas para garantizar el respeto de los derechos de propiedad intelectual, incluyendo los de propiedad industrial, lo que implica que cualquier innovación basada en inteligencia artificial debe considerar estos derechos y las medidas para su protección [9] [2007]. La jurisprudencia del TJUE tiene carácter vinculante, lo que significa que los Estados miembros deben adaptar su legislación nacional para cumplir con estos principios, asegurando así un nivel homogéneo de protección en el mercado interior europeo. Por lo tanto, cualquier desarrollo en el uso de inteligencia artificial generativa debe alinearse con estas normativas y jurisprudencias para evitar infracciones y promover un entorno competitivo justo.

 Conclusión 
La legislación española y europea actual permite proteger las creaciones generadas por inteligencia artificial dentro del ámbito de la Propiedad Industrial, siempre y cuando cumplan con los requisitos de novedad y singularidad.


