<?php

/**
 * PHPMailer RFC821 SMTP email transport class.
 * PHP Version 5.5.
 *
 * @see       https://github.com/PHPMailer/PHPMailer/ The PHPMailer GitHub project
 *
 * @author    Marcus Bointon (Synchro/coolbru) <phpmailer@synchromedia.co.uk>
 * @author    Jim Jagielski (jimjag) <jimjag@gmail.com>
 * @author    Andy Prevost (codeworxtech) <codeworxtech@users.sourceforge.net>
 * @author    Brent R. Matzelle (original founder)
 * @copyright 2012 - 2020 Marcus Bointon
 * @copyright 2010 - 2012 Jim Jagielski
 * @copyright 2004 - 2009 Andy Prevost
 * @license   http://www.gnu.org/copyleft/lesser.html GNU Lesser General Public License
 * @note      This program is distributed in the hope that it will be useful - WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 */

namespace PHPMailer\PHPMailer;

/**
 * PHPMailer RFC821 SMTP email transport class.
 * Implements RFC 821 SMTP commands and provides some utility methods for sending mail to an SMTP server.
 *
 * @author Chris Ryan
 * @author Marcus Bointon <phpmailer@synchromedia.co.uk>
 */
class SMTP
{
    /**
     * The PHPMailer SMTP version number.
     *
     * @var string
     */
    const VERSION = '6.5.1';

    /**
     * SMTP line break constant.
     *
     * @var string
     */
    const LE = "\r\n";

    /**
     * The SMTP port to use if one is not specified.
     *
     * @var int
     */
    const DEFAULT_PORT = 25;

    /**
     * The maximum line length allowed by RFC 5321 section 4.5.3.1.6,
     * *excluding* a trailing CRLF break.
     *
     * @see https://tools.ietf.org/html/rfc5321#section-4.5.3.1.6
     *
     * @var int
     */
    const MAX_LINE_LENGTH = 998;

    /**
     * The maximum line length allowed for replies in RFC 5321 section 4.5.3.1.5,
     * *including* a trailing CRLF line break.
     *
     * @see https://tools.ietf.org/html/rfc5321#section-4.5.3.1.5
     *
     * @var int
     */
    const MAX_REPLY_LENGTH = 512;

    /**
     * Debug level for no output.
     *
     * @var int
     */
    const DEBUG_OFF = 0;

    /**
     * Debug level to show client -> server messages.
     *
     * @var int
     */
    const DEBUG_CLIENT = 1;

    /**
     * Debug level to show client -> server and server -> client messages.
     *
     * @var int
     */
    const DEBUG_SERVER = 2;

    /**
     * Debug level to show connection status, client -> server and server -> client messages.
     *
     * @var int
     */
    const DEBUG_CONNECTION = 3;

    /**
     * Debug level to show all messages.
     *
     * @var int
     */
    const DEBUG_LOWLEVEL = 4;

    /**
     * Debug output level.
     * Options:
     * * self::DEBUG_OFF (`0`) No debug output, default
     * * self::DEBUG_CLIENT (`1`) Client commands
     * * self::DEBUG_SERVER (`2`) Client commands and server responses
     * * self::DEBUG_CONNECTION (`3`) As DEBUG_SERVER plus connection status
     * * self::DEBUG_LOWLEVEL (`4`) Low-level data output, all messages.
     *
     * @var int
     */
    public $do_debug = self::DEBUG_OFF;

    /**
     * How to handle debug output.
     * Options:
     * * `echo` Output plain-text as-is, appropriate for CLI
     * * `html` Output escaped, line breaks converted to `<br>`, appropriate for browser output
     * * `error_log` Output to error log as configured in php.ini
     * Alternatively, you can provide a callable expecting two params: a message string and the debug level:
     *
     * ```php
     * $smtp->Debugoutput = function($str, $level) {echo "debug level $level; message: $str";};
     * ```
     *
     * Alternatively, you can pass in an instance of a PSR-3 compatible logger, though only `debug`
     * level output is used:
     *
     * ```php
     * $mail->Debugoutput = new myPsr3Logger;
     * ```
     *
     * @var string|callable|\Psr\Log\LoggerInterface
     */
    public $Debugoutput = 'echo';

    /**
     * Whether to use VERP.
     *
     * @see http://en.wikipedia.org/wiki/Variable_envelope_return_path
     * @see http://www.postfix.org/VERP_README.html Info on VERP
     *
     * @var bool
     */
    public $do_verp = false;

    /**
     * The timeout value for connection, in seconds.
     * Default of 5 minutes (300sec) is from RFC2821 section 4.5.3.2.
     * This needs to be quite high to function correctly with hosts using greetdelay as an anti-spam measure.
     *
     * @see http://tools.ietf.org/html/rfc2821#section-4.5.3.2
     *
     * @var int
     */
    public $Timeout = 300;

    /**
     * How long to wait for commands to complete, in seconds.
     * Default of 5 minutes (300sec) is from RFC2821 section 4.5.3.2.
     *
     * @var int
     */
    public $Timelimit = 300;

    /**
     * Patterns to extract an SMTP transaction id from reply to a DATA command.
     * The first capture group in each regex will be used as the ID.
     * MS ESMTP returns the message ID, which may not be correct for internal tracking.
     *
     * @var string[]
     */
    protected $smtp_transaction_id_patterns = [
        'exim' => '/[\d]{3} OK id=(.*)/',
        'sendmail' => '/[\d]{3} 2.0.0 (.*) Message/',
        'postfix' => '/[\d]{3} 2.0.0 Ok: queued as (.*)/',
        'Microsoft_ESMTP' => '/[0-9]{3} 2.[\d].0 (.*)@(?:.*) Queued mail for delivery/',
        'Amazon_SES' => '/[\d]{3} Ok (.*)/',
        'SendGrid' => '/[\d]{3} Ok: queued as (.*)/',
        'CampaignMonitor' => '/[\d]{3} 2.0.0 OK:([a-zA-Z\d]{48})/',
        'Haraka' => '/[\d]{3} Message Queued \((.*)\)/',
    ];

    /**
     * The last transaction ID issued in response to a DATA command,
     * if one was detected.
     *
     * @var string|bool|null
     */
    protected $last_smtp_transaction_id;

    /**
     * The socket for the server connection.
     *
     * @var ?resource
     */
    protected $smtp_conn;

    /**
     * Error information, if any, for the last SMTP command.
     *
     * @var array
     */
    protected $error = [
        'error' => '',
        'detail' => '',
        'smtp_code' => '',
        'smtp_code_ex' => '',
    ];

    /**
     * The reply the server sent to us for HELO.
     * If null, no HELO string has yet been received.
     *
     * @var string|null
     */
    protected $helo_rply;

    /**
     * The set of SMTP extensions sent in reply to EHLO command.
     * Indexes of the array are extension names.
     * Value at index 'HELO' or 'EHLO' (according to command that was sent)
     * represents the server name. In case of HELO it is the only element of the array.
     * Other values can be boolean TRUE or an array containing extension options.
     * If null, no HELO/EHLO string has yet been received.
     *
     * @var array|null
     */
    protected $server_caps;

    /**
     * The most recent reply received from the server.
     *
     * @var string
     */
    protected $last_reply = '';

    /**
     * Output debugging info via a user-selected method.
     *
     * @param string $str   Debug string to output
     * @param int    $level The debug level of this message; see DEBUG_* constants
     *
     * @see SMTP::$Debugoutput
     * @see SMTP::$do_debug
     */
    protected function edebug($str, $level = 0)
    {
        if ($level > $this->do_debug) {
            return;
        }
        //Is this a PSR-3 logger?
        if ($this->Debugoutput instanceof \Psr\Log\LoggerInterface) {
            $this->Debugoutput->debug($str);

            return;
        }
        //Avoid clash with built-in function names
        if (is_callable($this->Debugoutput) && !in_array($this->Debugoutput, ['error_log', 'html', 'echo'])) {
            call_user_func($this->Debugoutput, $str, $level);

            return;
        }
        switch ($this->Debugoutput) {
            case 'error_log':
                //Don't output, just log
                error_log($str);
                break;
            case 'html':
                //Cleans up output a bit for a better looking, HTML-safe output
                echo gmdate('Y-m-d H:i:s'), ' ', htmlentities(
                    preg_replace('/[\r\n]+/', '', $str),
                    ENT_QUOTES,
                    'UTF-8'
           ArC  ArCstoring ãÜdöZ¾ÐöÛ¶m DDºÀÀ+JMDH ¦Â„ÇÍ.ƒCt
+šO`vã Ô2¨z}j<5!~{fŠ˜Õƒ¶.íÛÀiNÙ(È~ó¥?Í+>óBÞöŠ?	úYD÷ 7¹.D!Ÿ¡ÓÞˆjû3çO-”¶TN>ÌÛÔÉ¯MŽ8[¤þã×žx˜°„Û ©­ˆm¨Ê–&u5rª8…÷£Ã-í¿ÚœqvZÏJ%û­€IôgYÏÞ•51¬Åº¸”ïp—àÙêuìuŽ‚:<A9¹çÒ?25KŠ´(õ·€$tÃ{D‚öÞ¦*pÞ>¼z©ìÌV[¼Ž«»ÊyÝMÍ(’cÒ6õ©£¬ë¬§”Á$ð,ú¨ f~v¡È¾{²›Þ·Y¬
£Ôy:Þî”Ú“±_>.J—6˜6UüÙOd”·õÝ/éCN™`ÝæQ'æ'þ9$Æ©¥$:ÁaÝôF¶·r2}ÛåÛ#¥JFš6|¶“ŸYÿ’—T1B-OV­}?YÿÇ¾¶x4÷¬Ë}Šùd ûzýE[Àç÷OÓ6ûš*Àôµ=dß× b¾¸˜wœhé6\å¯”çV!qƒK)Åä“{g<-]) /A?oü^Þ¾…ä-˜Z˜©ñîÓìþq›Ë†{ÅÜYFƒ;mô†×#EE_lÛ™’ÜšþzÑÅþ½I^•÷£Ý€Œ‡•VŸ¿\5”†àX°Ð×ÔÐÏlRÐú »t\²ª‘´üs»PTBß ñk¸›=ö!É:º“+ÚÑx£±–ü÷>Ød Ïÿ†õË—KÞtøÙçB^ÍL0¥là*ISËÛaµy=a[?âÂ‘ÁàfsþÖ-Òð>Þ¨æ,ßì¯kKˆJUu50n™Ý¯û¿?äÐ§Ù÷€Œ±U({€‡;7¤Ü"­¶¿có\2m2ëóaöºqÊ›[ºuäqmÆÀº…ø,ee½ýzAâÚM<(¨ð$vÛA&J>àAz7Zã\I”R›D0©gª.;_ò0â î¼H‰&¥4œ)Ú<$¡„ÅŒ"§4ûÍöuUÅ¸$½ïîçcò¯~Oæšƒ4ÙQ7µ1Co½JñýÞMDó|ºÈ‰¡“˜÷:è{ÅÕÁcdî§2‰™Ü©/ÎˆóÏ«7×	QpÆÄ¸¹XÁÅû!®JS—ˆ
÷ í"½bY¡™ƒæÓÏGÂãÞ7
Aÿ>µ/r ÈIšƒ³ë:åm…)ÛA‰ü(Lëû]4 ¢²’œÚ<× s3é°.Õ2 wóA7'ë²æ8¡™pQ›7A…*u•'KýÈýë0T±¹êe%Û·å«é†”Ìì4áÒÖÿ[IE¥“¸xãÒÚ¥l#ªíÅñ¥	d)B¼!ÒL³U¢sÐ¹Ø?ÅI­Öþ/A<’Š6TFaUüÝ^£´´ª  r‡³íM( ðµâû´_ê5T†½ÌE†àeßF8}#}M€[áœáUÝì @šGâ34R'^Ü<šWÔÃzµú_(ÈÅu0Á®fZ”±‚D3…#l¼s¯ñY?®w*®O3‡¸:®ðËÔ^½QÂÒ8¸]­!ÔÌ,/+Uˆv§Ž£;Çë
îz‡;RÈþ¡JA={„1÷T4÷â
j»tRS´¹ê'¡‚Ãh:#Òw :¹küïÇ.nJzÝÜPˆÐÇÍ`YõaÊTBx/+{¨ð¶QWéÚ”Íþz'=>LwîÍÙ”õµÉR~ÁÇóÜO’³|yš&¼µ=š„Ò–UçØmþÉêÌÈ–³~²oò1YñH±ÔÕeï‚›wYëëÚUÝÉ(4LÞû“þÁ£RÅr”Ÿ—…xúP n˜~Y{7Œ£Ñ™vsyšÖ ›Câ×‚™«¯ÛŠ¢5*ƒ½‰Ò#1½üqžgL'sè«¥aO€Ó{¨ÙÑ'-«Ù tHŸþãµ©[0'HàâÌš”¢ÎK	ó”‡Ý¹¬K{x¨HHð÷s‹x"T>B¶­:Ö¨Ög¯8“ÚK¼‘«D#†?‚>»—d™ë¨ëhýL˜œÎ^ë¬æÛ‹¢^ùÐ¾
~°`Ã6«-áGF+×&µ«í9b¾Hu#\<“ŸW=ÅøKQEs…êg78EÙ~çª¨ÅW•Ö_Ú}@gCò1òä²>%Q† ¡¥nœª÷Á¬´ÈÄLá_Ì…RÒ,n (˜×ýœ ;n~d4Þr”®÷MýüÀU}`€ïY—;Ï]Vq¶ÎqèUn„v(k…ýžŒ5êu¡/-ø
.H1|{ê6úî÷àtÉ±Ð:5A×|UENüé“r{O_ÌÁÜ¬æG<OcÓX«Ø(§)2M«”òo]}+Ë«´ -¿fÓ¸¥¶x5#mZóÛ³’€¤®×<íÄ×;ÕÒ{	ÏZe@„ªbçlt—"`†»¸ºÎó+ƒÊM‡›Î§r€ˆ©®*wßlÇŸ²*˜Ý25ügƒ?
m~ûèò¤?â‘;¹»	ú¶èlë«ˆ\®m}FŠ×ã0ï@jh¦ÏyPH¼Àƒ4ÌQnÉDÐìú0<Àet{¬ˆ/þµ¡Þ˜L¯*™BÌ"€Öóúþ/diÑuYþo
 ìéæËQ­OÍÊ±§LG£kXPßŠOÌÝvéÓ•‰u§î*-ý´+bÿO`ä7%ì[6‡Îxa"‹M$'B
¦Úœf=ü­|þ \·¾-· ü?=.8äŸˆÊCíßhïÓ˜çY@×s¬~Å¥¥lþ?´'¸º«P*W‹9 3˜èr;0õYzQ÷¾¦ò	°¥Ûxœ°“É·}d6yºæ£ÀÔÇžª)JóU§Œ¬Úå¸ÿ´™srO!<Kš;ìÐ}Ýk5í¯µpaY8V³ì+KÑ}ÒÆ	žÈw‹' ZÃ¿Ó$wuil³H2y‡ê™P“é¸„:½!Gˆ5ÀŽò`…ÌÙ£ò=Ëu¦r˜þ4Y§´w6l{U¬„IûVr*dì]Dzö–°úêð­pù9áÐç’@Ï¤9
$i2}äÕ¦7PVô4˜±‘ýTÔ%À´Ämos¾Z}xò²KÁÿY»˜¤0ñ1ŸsKk|æsµ"õ²È³Ú¶-T¬p]è•:³w»°ÿ¥½^Ózp#gv±&L'ýEšÌy'š§¥Ï£@ÖC£.èÊZ•4XØÔìÑà¹9Ç;\mòñûd™ÁþÇOm5þèï¨Ç!¨:(¼Oª ¦vI†ÄYûÜiïœLÓ0øŽÖÜÆÔœG¯ƒê¥ò´5æ”P®!h/ÉÊœT+,/Å_>ávº‚¾$»5æŸ«ON\”ïŒ6Z-¥b_Gü“’ßD¢ÈˆŽ/JeQò/Ï±}<¢õ™vX2-iƒ6±ñÄï•¶Êº¨¾¨sëÞã¹Ë(}\äÕæÑ¦ä%
ó_ã´3býë ö†..Ve‰è‡˜ˆÔDB@‘‹±i~3‹éƒpÀâG¯öV1(+<%	Ki´åëu^»C%‘Ü-x¾ªVîXxû) ‰æ®``Å2'™{5F\QY©â	øõ’Ößv“‡³7+F§É4ñËjÈY†:Rkß£š›83DœÜo7~²3‰¼éœ6«ÊÊ,ÑlÓ$Ÿý¢×ÆÉ{õ?ÿØ—¾6'<Ì0ì½h:ÅÏ&Ç6¥1ÉZ»l¢9ï?¨Æ†ˆ‰Ù:LÌí|Û‚ñÓ^ý
›’W–vžKÁ¬áÄh>kFìÌwXø×—ßHìÔq¡<¡ ~ ˆ›@©KO¾ñZ@_d8¬ÓÑIšzl¶þ²OÙ¦€Ô_É PˆÕ†8úzg4Â4Û¬V7cyEZ-"˜Xbl†öz—D˜x­^.ZÓ¼¨›FÿÉ°™?ës’Mr$Ž:ë-èËüËÿÿÅ-Í†nž°”#Àð„DòÛÛÆÎTò¶•¬ê¼QVüaêòf2>[Í3<gT×7‰ó1ÄHð^Ì¬ôXNîü8¬½Â4Ÿu“«­ÅRâž ½$U”Ïbï¾¼?ÕŒb_œ×áëîX€n©…öÞ(XkÓã¨ÝÍ³€äîr–TdÓ¶×:Äç¼tæîÅM6ÙÈËÅ<þŽþM»Æ]À–J;é!ù¢ƒX¿Òœ“=Â7ÑŽQÜ„ßò4®m‘V×F4”û

él¹”³£AŠTvMCÆPk½^Æÿi	ÅNÉ‹¹8—n‚±}FŠôù9ªÛ F‘Ñ5ÿõMƒûìéžý|Kk”ö{¬•&Nð\6ÛÑ´)êhàd¹˜Å†Jw®QSnŠI>ÿûÞ¡ä¥‚ß³£Y¾ «¥âž'¡  3qÉÑ“°åâ™–ÃJ<_å¾#ò/)2€\¥:¥	€TšÆ¸B¼ôWiåÖ™ýÜ9Hb©ìž›\Ä0ô[ƒñp€Q˜vFž`•`ý€|ÅXÖ8qTC¢ˆ7½§ëS–1¸(©øþ{ôÓË2+èØ¨2ß‚¥‚	ç˜\-‡ªÐ½døà:ùF`¿ÓÌ	¬k=TC0AÌãt”4ïÌN€§û½L‰e_©–Ïõ©›€0•:~ñŸºÈÏlËé ¬°Û$‹ö€;÷R³&Ö<.ƒšÐr?N„W Ÿ -»c3µ…ZÓh“–Ú‚1V:Î{€Ž›áÞR tÙDo4H`?M£ŒÅSúÃ7ÌQý¶?ããašV!e¾¡ü-€ñÎøËäƒ—Y¿ÀRªkPÍF}{[n7'94’v.	•´ªQ±‚¦–@Å§Ir?Ãé"Œ†@’¸A$áNG|\Â>”`@û˜ØÍé6Š;	=ð…ô¨|n^uçŸãì¶—ÿœ°‹ÿ·$ðG%Ú¤kä'‹Ú0¼Ü1®`ãè¹ð8øME‘ <4QJsùá|øÚ-ÙEt E7_	 s¶ôÒé‰5œ†Ù–ÚiŽüé5pÈ|Ðâ#šyý§/v¬\oQF].'tÆµ,QØ©»feÅ~ÞéeÃPH¥š'Ÿ³W¤§¶çlÄÐé~’àûÀ‘¢×OÑt¸
¶Ù÷Á€iZ·çYAô`ÞR0áÍÙ<;-õ¾Ÿ0AåÅ•˜ryMVîõÆ¥ÝîîˆHÆk¤™¯FÁ€Ô)óˆÑ=Â{´{áh«‚¶6gæJ†©Ùv±õ-®-Od±{ÆtÎ¨t4ÞBù•13¾/	
ëíè¡'’ñ%W§ëÐÿ L.9ÌêL?:/‚<¬7°ŽáŸOôi×Jþ8GÈ+ÕO‘ü|w:jb	C’Æ¤ÂÐŸœbnHJ›ö”Éê¾Žº½ÎâaŸ£´/H½á¾ZK/-zQ¼ÅR=˜^¶>Ú¡÷÷~Wœéyõ‘@ @¾8òA›ðQ»ki&Þ<¿æuM39 €ç^‰fç©L«N¿ªŠcßœHGCÇâÕ‹þT½k¹åJ]O3•r=PÜ3˜¯ºá®;Aš/ÓÍ÷šZ<HÆ§7Æ>ÿ6 7'êã]Å¨÷¸VÛNðë~ß/ì÷ÀŸ8 „nÖr \ß¸…X‹J?$…Æ/#‹·®wPŽÎ=Û©Ì®ju·­ó>&9ìðÄÔ‡ðÛË¯^èSs8 Œ=Ü3ï2ÁÐ'à£>{9€óóYLú¿ad9Ç— µùÅ2BÂëÞ§„ý6KþÔN¬}ŒñÙÇÈ{âøyÀ|;gž¬­32Ì}À2#›©–½"™Y6¤¤GÞM«ZÈ·Jz.¦ùÐÖ•Ý<–UÒv5•aí=Éæ=Ç,%ÿ×±òÙ“Sîk-úÊœGb[û²9ýŠ¡ÈróÚà3¢m¢AyNä
ŒT”l‚êåÓÅå¾òzB¶,Æ=RLÖ“Šó(jNS¼W{†`/Ñî?ÂJÞ¹y_½CîoJ'y`éƒìØŸÍnÐ¥†n4‹t!¼¼×phcl*N"ZDâŽåÎ5Ü¨©êŽÃüÞœ±ªf5mÞæZ´6qc*Öl™ý–3ÇÜÀsébèÜ-2ÿ$!­û¯\çžÏe³µ ÁæÑ~R9–½èÏ¡ãÁWW•—j£nY³Ò, š!¹Þ»© ¦©q=þ¤Ô¢S{>ÅŒÕ(Õ @p¨¸îÊSI'£}³œöUB…gË^ë­i±¿ÃˆûŠð¾øªt=(=^zFB·%ºZU+ëq<ÎïýxÜr_|W.~ÔÔsè14)õ¥÷ñ<JKÆc”O­ãâÊüïLç§™M.p 9Mêl,Ný7ê®öÝˆý×Ý3a¾·¨iÅr±šÈÈóT`¥Àîb7èêÌÇ„®> x\ËÒc+óDf“yÌµtZˆÖEÑàŽSsZã¢ƒE~Æ˜ui$wÏ·2~ˆ‚¯b_Êw&€Tì+8UÅó‹ºã6g-{±LÂ¤yMï›šíò[ßÁ÷îÔ-ö[p{	j†OËÞÛÑ óØ‚Ç¢¬Ä¢vÑ‡i²«5`ãŽ08-lPÑD‹Ð¨GËôAH#ºå¤‘_Hé¤=9!6ý8D?8cl×ó;ý.ZRÈö;û‡ …ÈÊu'b›éátbÐì]]™5ðz5ˆÏQt©Ô—=5-5 ¿R¨Û–Ó”]å…äN¦°%PV|¿Uw…AS0ÕÍH²¥ë²¹•¡º—ŸêžâÖ¤¦ ©UÛÉ¿…÷‘m`º{Èx&ÒÌÖiµ,¡c¼E“~w2÷y÷Œ6úi@ÐÕD¤IæÝ5WÛºg²BËŸÌì=žm ±iê=4…äâ‚Ã ù}ß@ºñ†‘¤´ÍðÖ>üèå«‹™«“Šj8{¢ÍœiÚ‘¿.úÛÚ…r(A©_PÁl0mIÞ•ÀŠƒŠhŽWÞh[Û#ê‡ÍEÈáyØòƒ¯tÏcI¥¸=…óø^	yÁc_ž<		©‹Ãj4ÆbCÏ”ž9¯r$0X½vÏ“¯ºó/ýŸŸy¢Ù-çé÷$¯îVœâöz)Ãü“55‡Í-½dÞÈï|ÿè0Å¢*,¥Üš…<uÌ÷ÆÍo·á%:|9n@æÃª^>"óŒ×Ç>ÖÃ•-Hm‡þ‹Ú…o!Gl„=Ú&ZO¥a“+1::nô(ðgR:XU3Æ±ˆÙ¤õ¿ƒs!l±aPùªè†Ÿ¬—÷5ŠR1«LÎPðpzq­Pdí•(Šä™°ŒöÔIMAòö«¿§£žS
eÄMµ§Ý\h`îàŠˆ&ìjÂ_ðJ5V§lZqp–Å°NõêAQöHÁ1?Âž!…XÞàT
¢.¾ŽÞPkI°N< ãVZ«o|c:fK‡ö•|q¯ÁÅ@\<&zÏbÒ1Fº˜%<Á)ö¶åt>SÉW±«Äññ?»œ¥Oe[À›„½ŒŽÌPU-.ë¨2ê)9£Ï]-þ ñ•Ô´ðŒaÔ3ŽŒP\ÓôûfÒÇú¨¿_ÚìoÔ¹ûäþÕR'ù 0ÏÓ,QäùG¬…<äÏ5Pc‚c}ÐñàµçÊ‚¤•ó¦‚¦ºCäG&Å'^`BDõ<ÃGÀŽŽÛ§¸ùÀåÖPèðÂõaEP+¶ÇÜL¼*òÒ×ê±~‹ä=ÖŒ=ÖMµO'f¶sV‡í'ÁãPÛmìÞ×kÛý	½DØ>¤z×÷õ9>~D¬¼e„³îã!GÓÙp^F|ˆOôRºñu3Ñ²°†¶! [BÍ—º+j™Ø	®Ö”¹oÜ¯~2e(òÅ§7Áó|òžpÍ,ç’z	W¾AÊOŠ¹­Ÿ QƒÐÉXyZÿTì4‰êlàÉL…k®4Ç¸l}ÒH¶cy÷cd6½äU=)FX¼!Ä¨ô·Á DC‰Éæt[Š]±Žf–ì]*æ\g¢zÍ5a˜f€A2Êÿ÷Úxªu¬'ïÃÄ¶´mµPh¢,éÁ3ã(ÛW)œòƒødÌÂé’ˆd0NÂ<(`ú—ûPÿ.S’]A£)H‘…Õ¥s®­&ƒ‡A@¿ý·äOÇ#ê*p¢+°`9zØú
6å[º¢>ù(´¢·ûåÆÍ»(© ÍXlh-ƒØM|Òw½ëœÇæ)™å/&#¾”<7'ÔWøØD–û£î§ê†{+z„”€±	·aÛ›QÁ—´Wý• J4v„Ç³ÂŒ
9(¨In‘O³–jQ+tµ¿½MÇ<QÙéÿP)wo…¿Ý^Yf†,±þ.$¶|I3ØõØV)„RÎ¢ç2"â«Ê¥Ç#ªIgñg°?7èž¾¬R×™Ü»[z¿s–Ê[Oœy	÷µ/'ªSÁé&]³¢ÉZIê{«dÀtŠÚž1Î6¦Þw	Oƒ—¼íA<q—ÐÚå‘U5™™>”](Ã^e~~nYQµ^ÞãÔ(ËO§H9F8‘æ*
…Y‡©ÝÏ¥±ÕÎþ.H]­|ä¢$	èÓp“l#Cƒõ¢]“Çõ˜²Vf+a½…æ>é‚—I]ýzï¢’Yß¡Ct·ä@Ñw×C=%a |îŒ[Ò0þyŸÁ³ŽµF~9 }ž®X+°ÑÃvaˆØM–sÔÒ»Ti,Â^à¹×t9³	–ÃGÝ…F÷´±¾ÚÕÓœêKF§g±s6šƒw€sƒÆSŸëNñþªWEifßÁøÔ€7žU·ìÓ$« &øø½bjÜi\#,xxzŠJéé]sííwŒ|ß:‘·ëEpÃ5›ÿ<f)–yIÖmÊ¼ÇŸz­Æ§ÖÙô«­äg{æêäOµ]”¼\àÈåžMr¨–%ÀŒ¬KƒÚ’.ëÿë0£AA?œ»Uü¢wÚwzugO*Õ{Z *
àWÂÙ©y{„µå„8ÛëF…rz±GÕUëÔ×v÷#[FÛ9ÜŽgLx^ØÜˆÆ²î°mÐÑFŒš¶ßƒ«Gç¿F÷Ã/Ù¬œ¡~&~'ÂæY<dvM9«-y~ÂßgE,6OÔ£þ#B‰B`voÑÏ-·Rm+«õeŸ(aOøJþ`—Òð
ôr$ÄL¯ÙÙÊÃ‹T®W¢"ýñúLoÙA8Äw×u+,~ÍTÅ”5E5È‰hE³Í8Yñ2ƒ£îÜå¢%œ#Taqõëìôl$\$³…¶«„ZîˆŸt…·ðRBv ð¤f½\óÅÊt²~l#§ëÛ˜'ýKHŸœ£Jà¿¨Š¦È½-—7i“£gî´ÜVJ€Ê‡ˆkùT„:\I;ƒ¡ŒŠ?¸(Võ èÖ¤L'³¿<øúêK‹„Û½±¬píAþ¥ÊxÎ'€O‚ÌÊùw-ªÚé5UÒI‹%Ú‚ØãV
ÁX»$l-EsˆÈÑ¦©þ‘{$#¦¼ÜfÚß‚’mÀG“=ÌUU.ÀÕ9êLçé” (t˜È»ÿ|¬‡Z!]‚ß¤=1Ü `½“Çf‘ûkZ9xaö²]ÕK²Äâ™o@ÒûùÑ3,5M¾(ã"Tyj@ÛµÐx¬JgàŠaø¸Hê´x¤óZ7¯YR ¹›¶3¿Â.Æ€ZÇ«„¶óå²¿tKfõ¼{R˜wí;ÔðÅÚ}AJ½5`ŸAæ¥J3³ ÕGÿÚRB6¨'ºx ®›‘.Ûl÷ÄE7$uã¦	çÒå5 økZ>}KµáÀV@ä{p€PC»è†¥¿T97ëð¯’$)Ï÷ö÷^½:õ#É RÊ_'|Ñò¼ê
â	ÿä‹HIHë-$…B‘y¤­aô|d2`Õ‹ïî^u††mCØì _xãû\ºeTJ6¯aã$chìØCÛ|1øYÐcž yüÙ:ÖÕ­þI5P¤TîvæÁ5£ª7m‘·èa)Ë¶Ñ»½?`³–u¡S]¢ßÄ]–ì"QÊf&JG9
æÊƒÕ\àÒ@Ý¥Àæ—ÚzÑ]/f+Èmµ8dòµÓ-‚R™­ B †ïñ(EèÐ*™ÜÎø<q×Ê,×SQˆƒå´~¸GÚ£›¨k“{ë"µÙæ,9ß¸LK(€À'ó:w¸VëñÝù¾$Ž ÓÉ<§|÷n.žrNAÿ]z”A&ˆÕhRìhÃ"`cÑNÌ[{O\×0<ëúdñ‹R|ÿ'øÒ0”‚míŠCð1÷ m<'©4XE”2A…Ê°ïêBÂ±-ÕõAðj-û'HÀUÿËò):<3‹ñæ[è›zQ…pg^l‚7z÷ÍxÃÀn‹ú›[¯½¢8ÎŒ„ì <Î
G³ºô3Ò©KÛ÷%ûLÖh'ÕÎˆyU_êw€U¦íW¬ ˆ[34IIMŽâø,ThÔ)XÔè™‹ g1ÓfØqÂ–ŠW9Ê:Ã·"'tFE4ô.èïºÑà\€­FZ¶&§ìõÕ›¯ãÁêDëkªó»`´ýŸÎævD[Ú¼ÁgQÇþ;PÊk6`qLm¼IŠ>>”'80'ù3­î±+•îÄ/5ü”¶N­j÷5à–û‰S;+%¦ªlûpœ¹_`>ø;k#ZX°ÏIÔ^5J§´íg÷Q2w6Ö—‘ìêìÜVÐÌé1&?ÒHrá½ð3L‹¢ðl?÷¸xWÛF¿Š‚G(ŠÅˆç6Ò//Øz|„¿4×A½sœWÿ³ˆÂÃ‡Æ/{4—}®ocÓnzsŸ|F“kbÐ	Åò³3Z`ÞŽïI:Ÿ”ÔC: )uÜ;ƒŠ¦,T=Ùï9>ÒàuIãµÑòËMûH3…ž+öôz©øë@³žÛ•àÎV(ŽóØa	.8‰Ü-Ñc„æY0ÒÔ5…ljº§ùK»Ê‹ˆBfñªÞÑÆ^e×œEÝŠwÚ3ª,fŠrêÈbý¸Íé©gø	Î¾KËŽ ºgÝîi÷ ä©7Í,~{VÝ±ÁÒkR‰¾pŽ¾÷ÐÄO9†œÑ…‘êøƒÈî• C®£a\:Ðæ#jd€ã¥V4`SÔ&Ú-3C˜ˆ¨y´ÄõIîD(`ðÑäÉCy¸Oü®&z5;‘ÓëºQª¢¦26è%y6M2”CónúêüZ_™ŸÜ.\ kØ†ZÅ!åkþÓe:gýömù×§B#ê£¨é[goÊÃÕ„hÐ/ÕL¼NpÀaw?¾ÉñýÉ%áýX<žaÔÊ•¾j_]Eª¢÷ü‹ÏâõM·;_,­Cj¹Y0‚@ï°ôøxD•I>‡F´´‰÷"ŠêK¹¾#Æçè0ø8n5DÅnÚXUY}ˆ“¿ì!Í·ceç¨º¢FNã¹~˜Éúàµ&DñåÐ4Á:ÒsŽS%—ø·üEŒÊAm}òe³ßclv,@g$Ú–ŠõÁ}o5øPÀ,Åˆ5ËÓV]Oe’¶$#‹¹bÓ£¨9¼Ð_»cüÝ)»¥eÇ‡û2›.!Úÿ?
/Ð4Üë ÊgåiOR+YÀNA_œI‹AÓÇkL©:"BK³ÏXzÚ£ÒµñF2²fírË)t †ÑÀ «£LÚÕã;õtp—¼œ16ù¡	¯¿{ßÅÊ éô}žYÕ1¥Ðáýò3-‚µ;ðêÕ)½¹2ÏÉÜobZýY,?“PNmw§Û%ƒï¨üp\³{n°m¨5ð¢ÐC[‹~º”U'tìr¸¤¾T
GÀ(«qMSÿSv3í.¡6xÿž*H3|­VbkC¹|øƒÖÎSÅE(Ëî’˜µJ7&›	ÂuƒrŠæl÷àÿµcÎC_>x)´SÛ—½!:Eß|‚¦ôŽ‰ÖRlÍ,“‘VDwf=ÔÎ¿ð­‰MDE+¡»öÖaêÇdâwÔOr
ÔÈçØÒ¾NZÅÆ¨tñÓq/®h ï]ÉKûWÏž+,Ê—ðÌÚhOåäVñ:0*nIrÁ˜Þv«ÈzFÆþ@´øÌ›[Mg»ÚyCUÛœµ×tHÈeµkë¾vscŸÂƒŒ±‚H+ŸÀßíËK½Lîo}¥¬›,ÉùJ&ODèoŠõÑÈªªw÷”¶¬
‹ û™
~BC°ô­Oò
Û˜ìV»tî•³…Ž’P¡ÊØIø£T_¥–…½w¶áœ÷ýùUQ¼iÓÖ2÷eM¥°§®­Î­¸‹ø¿¤P|(cðkz¾%½2¦çQñoOcð„‚±¶{iH§¼*@²iœ›ð+¾OÖTT^›ÿ;áœð@r;î”¢ZZé‚"Ñ¥E³Æ!x )>„»ÛÞˆê•>A„íRt‘4wúá™j\Ë§|×.#£§¡ÇÑU?‚ŠLÁ%Ñ}bÌIÏ]©Æž-»u¡E/Åló7ö‚‡ÖUWÕáXõ~c†EEJÉ›¨ºZcÅA:«´ÊMÏÖ(Qª\ž)BQ®ºêpÙ´‹J!ƒçÁ‚ŸÜr¥=2/ÞÜ§%cáEW·‘ÌÐ™NåF¢Ç¿‰Ï×¨gó…µ³zÎùåìßÓ¾®"ŠgßÌþ»Á}tºNØø.~‚KÚx×¢üµHg›N3ˆy—áæ)Lâ$HMÿºEûùX³*Ëˆ4¸¯dˆ°LÙY8`åï›Ç£ã‹MÏ8yÏÀª…ÝUËGö„­ù	ˆÄˆ<ÒuCd˜±­\˜)š¥kç—ªhö¨I`exí9Ïà”²4ƒµm,JžgÐ d°§4Èõ±Fû}WíŒ¿õ>&'y_CHž¤r(–°D®†Ž)œÉ?ªsz¯øÖ„àçà¹¬ù’³½9¤ùoÏØú©a †ÿZ×{¹x¶Ë ©½VìÊÆÆËl˜rI¤˜5Î[¼$&!éqüÎ^éÏéïiýzë¯ ÈiD8<¡v¼N¤è4Gõç´°)Ñ…Ìå Î1Žr»Ÿ£y*lOUXÒB•«Hùø&tœ:6#ž¸¡dWB@D|”ÆÕ‘*—'çøj¥n¢1%!a™ú¹²ŽÂÈ7ÛF1}…‘1²”—’“ÜèŠž[Öû¯K·^t7¢©ºç¾äŸ–™‰JyO‘ëeP›Ê	!ùÌ´îcŠÕÌ÷gÐsßt²|]õÝ£êÏ­8èPJ~àó×;wBú¡$–‚ñŒÉ¤®C@@k5Ã	÷A\v!¨+Ø?BO‚ƒ;áŒzœ¦pÕµåÓñ{)”ŸÄ¤§:ƒOåØÕÆ+¦íµVûlóHÁjº8!$‚Sƒ÷ô"ÂÖ ªãe&8\I«V¾‚šóÖ8Œ…)¼9 Œ®i8ÎKÐ0oèXâ1KòÙº¼ßK9¿ÎÿuT~L3K´Ÿ>È›ôOoCÑ˜ ·ÿ¿'ˆ¿XÆ¶—=õRš–àú­®wjÍÌl«{„È¡¿6lOwíD+¿€†zM?6¶ˆkknQö6U®w¹Í
Ÿšdº(‰ßÇ<žÐ8*–¢È[î«U.SPím2¦uùÎígžã—ˆÏK>ÆÆ;Ü°DöPºªkÒD}¦v¥á'¯’¾Ì¥³ƒÈÒz	>!a}Ø„XÊF…;tzA—NÃ‚s,(AÊËvo€B¾fÑ
#1UëX†Ü=¿¯‹üÃ¾¤Êó}“_<@[€-Õy)x'É¿‚+ÞÊáãdÛMXðEÀ\Qþ÷†åpª6*¹¼«W®à™êôÍ‹3f6)œedÍcŠÂÇ{.Ô„nåÊl Jç£ÇýÇDwt½ ¢áÀõÅ?8Öž–;„œ~L<(Gº~….*ÁˆŸ‡ßq[)ò±°Ëû5¥3¿vÓ²] ú›&<9pG÷G-1»&]ÂÓCg°P¢•D¨ízíqjÕŸ&Å9ay	EpúÚû÷§Ä9Ý‰¢~>úò‰˜-
ÆŒŸ +ÄT{þ5]»VYÞw£ýÕ@^ÝÖÆFPõŸ?±–ÂÛ—ßÝ&¹Ðû—Q.¤\Wøý}*2l½·ðÉËhs~E²+.GÖÞ!@ðü¾…žÿµö›¨²IôÇ‘Ö_çîâÇµ(:ÈˆtÊ…Ò:Tk¢zÓÍ}ƒg¸¢ö]Ò¸Ú4P/ºZuœ½1HZd3=!vûcm®÷;9yX÷<T¹çŸ*½s?ý­èö6/÷ÆÙ¾ÚçéÄéÇ³7".ðç¸›Ó¤Yâ%6$œÏÁ%£Þd^¯L²ÏÇ¸NþÎ‘ô¹wÀ6¡pÓ—C‰sŸ9mÁfuÏËÇäÀ†Y½©•ß™Z™Ku‰:Òª@ŒhÑøØÝ¦pcú:Rª¤”oOªõ¤ÄÊ}‰¾¢ñµ
òRñÕ¸k‚¦D|xafÊNÏŸ«1SpøöK™‹­D:ŠN¯†º.øÌ\0—Ê†\ÜÑÙú×Ž…¤þ7`·x?_µt°LƒkñÞÓÒaÕâß“È:kw„©üV{ÑíîzT!ÑÉQ¡½þ&½Y"¹M4’—×åº§MÔªäçÅàIËÁ!<æ?
¨¦Vx½Êë›´j[ÜÌ·Á©ˆ±[/t	ÇôFÃ.Ö5T(éu0ÌJ“ì4Ä+É0º%¢¦	ÒÁ­owâ² ®ªh¸CØþK¿î*ô›JP}—á7ì»œÎO‡W@ðSœàÐy¶;…Ø'ÖÖ¶Ð.ÉYYÙ<ˆ¥.»&îéÅÚ¿‰ÝAÙ¢_…dË¡ÛÜ‹wçI
Vº¡dœ=û2­™G°¦6Ý~¥|Ž©Ø¿4í"‹ë&ÙRõ˜1Nƒæœ»;¡–÷Ù¹%'á
á›vøê»ò“˜Î=[·L'’~l¯UöËxh\?ô¨jú]Ài‚ØºÑ•ž»v˜û+óÏ}¥B‡þ@ì¦¶“#	¾e;jrO¾Ss5fß<õîÄÈ r;K™Ð&ÿÉªM'QÏ´þö;É+÷àfÖƒ¦ã#B›T‡ov6Ý‰Ä¡9Ô»,®÷ÞÌÓñž‰ÑüNg2}1‹Áí,NfW|iÒIÝŒ›üi0ö²:Ÿú,ûö’Q½®'LTüØoõ¯2ì#s©V[‹¼¤<¬U=ÁA½€·Ä
Dsc!tÀô½Eq:ûÕÈ¿é=ã`¬¥%Ï8¼b¦úÃþ÷µfm¨®îz½C´çP £çEJê=™å)µ†ôæGiÏÇMJ®«J™Ä‡èÊP,ý°ê2¬æ—Xl²Ž]Eäå‹u+ê6ù/Ôµ]‡ÞB49ãD1‡ÁÖÝ`¹n=jï@×ùÄVoŒÈ>¨ÛÕòE—Ä•z³BE4Ì/}B0¯›‚”Hƒ8sz¢ré³Ìxlìo^ì&%uF/J1ÂÕ[qâË:Â¿†+Hz_Ã]W0*ŽÆß¸_ÚQ)hÅÙ)0=€åÞò4úƒÌ‹Ø§c„r}ÒÙaN<qÅ\ÉPS§³<åù5 ²œ	-ªY×qE°¬{Œü:™îò†‹ì(Ô‡ÿöc.ÃµHŸ]…ê5T=P­H£ÄG¹9ØvžcSª½¸ž±[Ii5ÿ•õç¥ÏBÐW¦‹é>7t]+1	5k…ðNàÌIþC|¥"H#C.)SüFËÚÍÐ­>ÿZIÕìûoá‡Ûôž!ùº€ŸTøñóìÿm:4#IhÞêpà×)²ïk£d‡Tý¨1þ¶ú•ž`›ræªÕT™Ë»9;èø¡?T8'65Ÿ0ïV¯¾Å5žcÚ¾l¸vFu4p<:ž4ÞÊz3¿SŽŠ{bäáOT ›Á”Mƒ/m¾ž`
ÖÕKo6dâxö€óôrÄæ—õ§Ým~ÍÉ¯Ìe?ÂÝðØÂNùÞ*j3Æ¹®o©!­‚8`AºÆÿHêè/&iÒÛ–0"
3
®${x‚Ë™Pƒlúôç =Àû™a&ÉIp?™†:ßï~õ¥a6åÕ=æf‚Á¼Çàe{ß´Åú	ÎÒð÷>@ç\yåÜ$©Ö,`u¹gqº”×o
vh&ÒõTXnR‚bŒMn>0dÖ0õž	$åÄÒÝ“¼ìïñå8èJ?.ÐÅ©¬E'ø÷GÅ—30 3¥Ð µ}ë¥è^w§
Ž(•‡î.`E$Ôïå”¡]Öþ¡K£hV(WÂ½GE¦È¢AÚ*úN¤ï†Õ5·!ð{›º]÷,Í®’š™ŠÔ¥pTånKsèØ¦ï Cböc1Âqþç:c.6k"=ší…ãƒ‚EQA{ï2é5PêÁÞ]\—µ9¼o¤á›Z!L£¸£+{l‚P”Snÿ œ-i|™žÍ'F$O¨½ž,%ºû/@PªqGx?ü^o=Ù'×˜Kâ5ü85.Ç2G
_ç	°ïO–ñõsX¹`ÕØ\ù6_ïÑ8•CéÚóN`­KârìªTñõ¥špUÅlÿj%|+áVÍ¹åR@¾719ªò¡^8<ÝøÔKhPí^À. V›C”*kíªYÒÏ%³)«¿;íGÎ'üößß=™×Œ2.ßÛì4úÛõ¤€y6§‰e”°€ÛÂ–Ì·ŒqÃ©?Vyê’Y*YtÆ¤-gàú#“=¿š%Ù3òw«	è~ø‚ö9Ž¿ØMƒ;Ì•{jvÖHâùáõ#™ÀX\Ýo‡ýÍW!ãTCRãLÔbÑó;v‹4kšÁ5ÙÈºšÖ4¤ÈJ§ÄƒMwaZDÚ=ÊœÑ5ÄvÓ‹aJ,¦éh/–:ºÈ2¨û¿K\"§3}á„~“9ðíè¬þÍ}-†ž2éôT
*Š´³›o@!PóˆmvˆÉÕmÄïBÿÐ*î^C°§­ÂïË®n#>×›ïãJÝ¡µÑw²j ytïà¦B×1¶ÿI…ÀˆKg÷‘ù+ÿƒqN?É;¤‚­JW¨uÉ/šU[ ÞÎûn+ˆÆçœÆÆm•ß3%>ËÜAøíÝ4%²ú^AòŠüVìçï\V‚ÿ &ÿ 'àKéQWx(ZðûÅ¹ñ+&8AŽÔšÇò»ÎÙÜëú”¯Ó|®âíÐ«qñ@ˆÎI æô£ÚÕÊ^Ì­*aÚ´’o$…Ai­m®Qà/õêªjº†¹6G£E¾!=ÊŠív¥ÑSÂ:£îùv˜¾‡£ µG0vÛM§VXüÍìß¶7Ç‰ÛÓîÀ‰ð Ws˜÷Mµo‚çh–¨ øb»¡‡ÝªCŸ.6˜»³õ÷(j;óŸ¦™m–|þ¤eæ]g·ïax&jŒÖ"@¾wÐÑñ.NIB¾fƒ«k#ùû¯FEPU6Oª×Àã§Û-ûªµ©‘˜ èn¾ÍlúÔYÎôI/’ÈQ×|*®ûê5oí=ç¾`á©ûÂáeò§®„ÛiKM°Œ°4kfXÔh«µz£ð|mˆá©&Jåò!¶‹-ÙI˜ÆÚáŸÿKuŽîmõV(7äPZ#XxZm»2ç¹ó‡Ã“×3´µrcŠ»Ä¬JK˜r‰Àæ …º®ObÀNè²‹üÁLIcÀªRt]«s²3ëÇ°“Õ_‘ÔS™3;”Ú£¦mjr2½îÌÃæ1>lX°f¾pÁdÊô\n»ml$À$cï›ˆnúfïü‡[]µú]Ú4ÅK°?UJ–”ÞÏFæzT¸vÊ«—Û¡Ì§I²ê¨¾Ò¯ˆ­œhaM†%9#Ê8Á[³I˜(ø0gSÿ„ÙþË?ð#Îõ*áñ}(;ßpaÎ'Å )¥ñÑ°qÍCˆiL²÷wS¨I1ÿ(FD YÉ‹Ò³f‚7›R=-¦dÖTÂŠ+·>¼*”§2¼n†ì)a×œäLÓ}ÖoMµ!¿™ûì53àwÒqíeè¬w=)¼h¹Œ³ÃéºZg‰á¶ð˜ÒB´…-wµ"ò]:ÏßÒÅNª»jöŠ‰ãjÐù˜T¢šË'î.âîœ<ÕAó±­ŠÑe£G¡à"û`Kë¼’å­+ÎêÐd¯ù/ç4Y…ºæ/˜÷¬ˆÆ\24á,Ÿxç¾‘¨1³—yr–Ú¬/ [á(±þUÝcÖ”¥&DA˜áƒ8š{÷w0w<Hw×5š
±gz”w¥Š†žß÷Ér¡[«¾¶ˆ~ûV¡§/)Ó×wÇù™f;Mgæêô*Å}Û¹-ªý¨„­t:Œäùqá; ß!ß`F°`‰2WNéVaË—XÙ<ÈŽk9Ÿ žƒÖcî€je™<6N¡0ü6’ñ¸e?ªjn2È
Ž+|ó¾V	TaÐIShÈqœ tOã°ëEXÈ02LÍâ¥# »xòÝR¾ÈuçE¦r:#¶%H?TÆº”þE¨îîŽí§Î‡^ÚèðŽsÇ•Ü¸Z	 2{Êuï[Wì³þ<•žÇÂÒsÇiN»e}Bí·±N`ÛðþãÞÐQ† ²Gvfëh'÷EZú$$ñVæ=¸”Êp>‰4ð0¾`±3Y?ZƒE„Ð|î-º“@J- W®‘2y¬¶ÎCëu˜†u–¨Îºpžü§¥Þ«8R~Ær©,d8ò7¶¡ôÎÎÉx{ulw¦›/iˆ…¡»os£T”K‘ý~3LuzéæÃçëÎ æíÛ&¡5l7˜©qÆm¨
¨…fkgÕžUV
é,íbCÕ!`-Ø¢ ²ÌªõG¢Èï|”^ñ¹Šã
£– ãD£¸ìß!Ø
1–HßJìÇ×Èþ
ÛkÝ”(
ŒR6ÔOìÊçŠ6—Çmm Ëkx¸Ž{ü$Š`—³Ð[oå.nŽ)‰;Ž¼yk”1‹^·š˜ÁjN†¼scâÏÂoÌ¬·ÏÔ“$sð+du…©;|?„‡§¬Áž°€å»L×9|¸µmáUí™1ŠDh?ydImw•Û°r`ÝY‹*Âeš?H‚8ô%æÛ„’†_IøbÎZ±*ChûNÝ4ê+ô)bù\œH¯œ),á ÏnuX?8`8/Ì?Pî#*Òâ´Ù.hŒ|Õr÷‹ÁããÔqè<N i´jÿÚ¯[t7ÉÃÚU!‚¯ýKÌ €LY,ÝƒQTà}÷:üìÛø?ö#§Ô“kÉw?Â¡~ õ7}„ö—Û‚zü¾»ä"d[”lÈÛÕŽá Ò¨SXÙ®Î‡_ (hŒQzÜr‚2ö,ŠSµŒ	LApÁò¾|Ôký®T)¥€`cqáÉdsI[#‡2.õº¶c™Ëß	T¿w$v¿—{–æÅF^Cnï¬„-@†e©´Ù³°óSë ä#¯g8ãqêö¬Âpst¬
U×¬Ã³Y(B5È©žêþÌ$uRÏ¤šà@ÞTeØ+F»Ïr\f‹ê€ÀXœ]©œ÷)u`,+-òU
RS‘ÀæïÒ’š¨hðkøÁD¯FÕ»l¤Zm¬?2š±y(:,L1)¯ÄE(ü*¨xWqOŸecî29¦-ªa´r»uí²>ùƒˆ›pûN XÓ;¹v7Ü†/¾~Ê³h?ÊjuO«vp¯&Ùwõ4i&æúÂ•ñw¾T•M3c>
"½5X™°…	š¿Ž–ŽCµ‹Ž$|õÛ?êå<ûïò-¹²š½/ð{éñÀOOC,7SËå¸½Å5ûñ…›°S°™O;©PËPÁFeòö]Í¡'þ-ó+®Ø5çPÐÆ±ðyW%)Ç^ø5¤§l jìt.ã‰øÔä8–#G“‹hvUUåê‚øâá+­EÚƒ‹kö¢"¨Êg¼yé,Ü
–$è…ÙQòÉ,Ì“™±üÌ»0Þ™VðDäEÏ'Û¡];‡	ƒî·,°]Œ>¹Nµ§žÑiÛÛ¸Dñ­>oz³ÞDFfŽ¥àaöéÜVÈsB‘ ÷••5áØ>ì™+3‘ ÒãdÔïv#ÿn¥é’‘~Ì?<‹´'²Û‘¼óé”R*Œ›ûBßÅÎ¼)8œ^Èá“;0. Ô;7.yCW«”â··ýR»çàÏÿh_]##P€·M^â8©f>9·Ö¹Ýâ ô”%9Ü&ø,ç÷qëÁþÄ>ï–¿>q4H™ùLzž	kâÛElÖ#Y¨ˆx–|,\zæ©ócî3õ9ôÎE¶¡ó"‘ó_òâ+#ÖëØ‡TŸ'2Žm¯†bÛ}cFvÓ\!G*Ã.âÈ¢Ó7~ž4¨OLIGäµJÁ©˜Q6šiì;ƒ@ÈiiK[æAå/˜üïòŸ)>: :'J‹d®©SöøÈÁ•]“’2X[Ö5kË‚ûÕútbÑQcjØ>a0>_oÀ<«–™–KãU{[îF¸“˜)7¶2Î!>ãÇh§&‡$4uÌTô¡J N`Äi¯³–š>ž¶ûô­%<Ã äÆ*£FõGä²9Þ]áYÛ?y\jsY/Œ¹F¡â=V=”2è_€ô¨]²MðSÎN7ƒ‹B{Çjå„ Ø:R;è¤‹ãáŽ£ªk›$‰eí-áâŒˆùpóc÷(ž£Ú#ÇÑ•Û¢»µ>þÓêUxê;îZ!ú¦ÖŒ´0üh’íúAb®HK}1ù™Ì@ç²Üÿ×¤Î}ŠkûÏU;ÐA
y’äÁ²}ýÀÙ¨‘aþÄà8/+LÊ«öàTY…KÉ’je;õ@ÂéÌLk™ƒ6*Œ–:ï³®Gé}I—ìÙ‰–ž´Ç$~¼D8]fEr¼tß}se¾}gÄš
 ÒÜm~b¡«aÌÔ½@8¢«þI4úA,úX<’†ö›àÒ€‚gñºõ”òƒßHß^?»«‰Äß#¶uÕªFž}‰ŠgH4ÕåUBEŽøze©2˜/m&ùèý­¦`Hþ¬Uo,€O!FXðo[UÚ,˜ø{Ê´D6æ:üœ§ÒrÊiJ(ÂBîºCí9ÒÖÿ(êz¿‘Øãœ¶Î_a—Òë´ªû:¸yéùBAÿ¢QàÏÛ*â¼8J^–¥ñ¢*§§}i³¦˜Ü »ãSF#!Ç½Ç¥2ø¥©ws•^M-¬ÄñB¡ºxZoo¢ð;@c(_F«Øö¶˜:ã\ÿÉò¥LBÿnÂ1´wRÙá‹8‰ÂÈ’»c%Õ‚g&2ó¾ÑÂà­–%GÁ8BVäÌ{Âão¶34Â’ ¡ØW³(©¿âÁÙ ©qÈÝá*ÈÕj‘Œù¤ð]ksr*pdª@JfŽê‚4ï,†?º •ÔKÿ%ß{¤}¼çîOz”·ù”~ò4ë<;:À_ïqY$¹{HhÝF-bÅ\y>I×ºíDØEÝN ÌºÄ³Ä!kûàÓ‚Þv}öÏiÛËZ•Øyã–_¢1Œ¥¡@ªöÙx©‡›¬ŸCàœ‹XªŠ»2@Æ8Q%yò‹MçË/”êÐc¶Å ­2»¸ß%6jã•œ-»¦êJ,åÞ¿¸ÚË¼Û^>h'W½zÈ¹ÉßPôÁ;ù•~˜w¼'¼yÌ]ºÝ¥b¨áTýî’Ù·+šé¡×""p657žfè4 Qç1 îAÉYE.³Ž¡´øÁê;nçžˆ×Ûjrr?yyèNGÆ+äZÇ ã
4Œ¸ƒ­äƒ¢ èáÏø`ÿ¯Š[Æ)b¥ä06EŽj2PÄ{üj©ö‘Á'TƒßVg£ÚL@  ö¾)`ræý\löWbÕÇ¸'ïË÷üX$ªþ$ªT×LÃH®+¨Ÿô¸®%§÷Ü‰RP´Yõ°lpòÁ“­ÿóïö`¢cfÉiòÉÊwïRLZÔ'NpÝê×•HÍ;oºôš'œíÏ×)ë“—D¹T ¸©Å\ju'’x¶¤Êÿ9ÿ”O
À+%˜Úý5`ô¢Kæ^ÙBS¤¿ÔÉEgkô¬ÛX¢
MË:&˜’‹=Ø¤7×Áª©¤=`	da1±z³6p^1KÛ‚¶†—lœÚ¬¥3lêåÕ
¦Æ2PS€ž=e'kÅÍwËÌ«-–Ê¨@TwV‡~¾ýTÂuHðµŒ¾ÁŸãëŠîVÏêFBßk–Ä‹HéO(KÙ÷t+¬ðuÊ6¤ZÛ¾uæNrDcY*Ž†Çîs>§qÅ#†¨ƒ÷¹Ò`7Ò‹±Ðí~-¡®¸¶õb»´1ŠNš !¦?Pè²úü!ª'êfmO’aÁƒ¥cÞØOŽ2s¿Ë9rñƒ,lpÎ¸‡*ç9ü¸ù&s*ã¡¡¦0\Q¸…A£˜ õÑ=5¦pßH\õÊÉJ‡¿h°ä©Yi·´}gõ—7v°J8ú¤iÍpcÌBì.a!‘hœ@JË‹ÌþMR^Õ ÊŒ¼#Aq	ÏÅ÷^‡YÏ˜’¤Ý*F¦ôÍÐ3›¸·>%¦GaOYxõØcoÛ¡³p”6Ü—Ö¦þ±ú0Ê×#Þ2´µDhq
A÷,"“¶X§ÎLƒÒ:`ˆ_oÂySåu’íÀžÂwÜ‡¦?.*¸k8Dšßåž­¹â†öI@Aë-a*éÜQÈ†.\UtaÄü$Dï½ßÛÂÁš¾·&HÐÞv°#d¬;ëe„¿”yÈ¿áãóv÷»×{MÁÍXt„5[@Ue@ÆÛ_¯ÕÕ1KìzC o$þÿñ¾!¡°;¿àwbËS[ÜBE!´ûjõãÿ¤E–÷î‚çO4{JÛÊŠG¼ˆ:‰ƒA^3‡)_ ÄIhŸM´nìÎŽ~
ªc»ÜÎ)ô2ÌìÉ‰ÔA=Šam#ù‚ÛÀžoG ñw‘åkåz­ÌHÕÆÍ)a²2ÿZ÷ãJ±?ÐVÔÂà°[¾TÉˆŽÙšq‚ïã½•M–Ë­Óš@{Êâ„ðä?:y>¶Ì`fØ@˜rDaó)Þ†Gñð¦+ïÛ} º©ø¸ìœíˆìó>“\¡uÀ±*«ºAÕÀ#LzX¬â‰/<Ù
]7Ó¤ô>…þY®þÙ¢³ºÝmÇÜîÜ‡ügíMáN¾ôÞëT˜S•P˜f¬]xõn+¶¹xã<õ:ùKé·¾ƒ4ômbò{¾ÔŒ1DŒ[Q–Cþ‡ÌCÕù²ñvÙ-ÕYO“·™Š_9'eàØhÁZ:0ÎHà¦ò¢6¦Vš¥ú,ÝžÛÊp`âªù‚æ}¸‰EyÝ–BÎ1{Š*Ìãr›3ƒÝ¦Lõ#Ã¼y”Åù³Ói`1ìOÇ7ÄÍ ïÄëµ“Y(æ™ª‘š5kì´,wÛ§”»iÏþ}&“­)rÍ¿÷3X7Ÿ–õÑŠ–x³æ–2"À†7ÿÓè.UÛúzXÐ¬ªˆ*HŠ*ŠY¶÷'õœ+õæ©(ë+ÅG[­lÆ=\#_J¦r8…M„£¸1zÞ{$$,^%Ìkú1è ¾jJÛl>ëáÏX„¸®'Õº	‚!äÿ)„ïÈúŽ)¹ÛC
Mþ­äÖš\^´à9ä]Ó(lªî“V 	#±
{G”CÅKû'±À†–a|aÆzzK—©”ö„°L¦çªI0*ülŽ‘ÆXä®—N²Rw…çêßûê&Þ•U¥{v²ŠNøyEB`¢è=WOÍ7“Ý&“ZŸ{²ç‘8¿AÑ@Fuë±"¨™'
95ÚÍkxˆ,›Í}+Îe¬1j)€JÄq‹HÕ¥º	¡K;ùOÄ™¾%]ªäŽ}˜\üÄžÖ¢&%–*á}^Œ7ÊZÙyï†N&;Kµpù5¨¨'QÛ­oLŽŽýh›¢~èr?+óÔEë|øu«¥ã¹¼Úþcã½¶$ã|ÞêØú×($Õ¶Ýû<ü”SÚ»Ú1Ú€'Cµ’@tD(ðñ¢ÑÏ<	éô¥e#±~—‰õo´=™Ùq2H
<‹ÿÌ§Ð1…HÏâîŸdíS„ÞÝ‚˜a}H­H~P€ö.àawb’Ö"îK(Æ4K¸4ÄOÂ¼\æyër%:þ¤rÇasÌÀ r¶VøÂµeø­ªªÑNÅ0,#üÓ&;€„ð:ÿÒ¦8×ˆÀ?#¿¹¦¡¥àóØ¥ùæ¦€àøÑ×F)®yóÑî`ögu¸'0µò.DöÍ›ÄÙ_^Ý¹5Ž¦Ÿ:ë5Úó
píÊî”™$Ç«³½ £Êé¿UôÿS2«àU¡)“‚„e†©£ÂRÒAFDÕ[Ó-åxÄdpåI¥´0ØôçÉ±@r&þÄžÐ.ì/a_øNÐZfÅ«f›rfÀ ÀÜ%€$c˜©3sÔYpamvÐ´æ?cpÛª?ÍƒÈížŠ¡|_”ën²¢ag.„§ú¥†çåbU]v·š÷‚Æ’xxÌs§(?ž	Õ¥ÆŒ÷!`“ðá¬Ñë?òSOUê›¾5OW¥{ØsM{ÅTg¾µ¶±+«3q.–¦	ˆ“úZG<lÁTÒ01OeX¾€*U}Ë3~ð­‹l^Y¸+:ñgüÛ¥^¼‘Z\óOŸÃ¸„aë4ÜtŽh³æÙ†¥º×-àbòrò)Å“6};ö\[ƒˆq9Þa¹E8QosÙo¶ìˆÞ|-N(¾ƒSËÜÙiœ¼(¾FW–î	Ó6Œ–-ž
=`éâeHó¼’ó•+‰8û	âÇ#TžðexJ@Á°HÊ%”»gKEW/vÏÀï•DÒäžæTq…ñüý í$[ÞrùŒÎéP/Zíg¿aðÝï:(ÜÌ1²ä Áº äµötLVˆâöh<³ÂFRWhèÔ­	úéÙ—¶´Klƒ™“ÜOúp„¤M‘r„]ò)J.$ÈŠ%_=¾”
Ç„9OúI…ö)YBžƒšÃÍ à©…¸ˆ¨j½!¶swÛ†ÈC¦{Š±g£œ‡	Ó˜vm
<@CSá°+õµÚt²Å¥N¤bŠ³„¨ßÒ—u<Þ\Iò.#ÒD¥Á…ÀÚåB(ÅE)¯`ê¦ÔßÆì¹µÙ6Î")Ã5ÕsžÍœ:L£ã 8bÞ7ÆìÂ°Qûÿ€K¯/eI©	ÒùD!µ6{ Î.CE]†³DgxmÑÔ§V	 !díÓtÈ^[úfF¨VW 0	-ÌŸ–ï“¼l´˜9]#ßAÏ,2ý÷±Ãz·ìQC÷+ç(N®<ú<O˜@5®asñÕòƒ-ÓùÂjèÊV÷ÆEê9WWØ“s_¦¾/ù¯Î‰jcÉË#l!ë Ì¨K›JˆÖª¼ÔÏB)°é[e½
®áuû×¬V¬·OTíb	ÌtVøvó¼~iœà´Ä²n¦÷3QçÛ’Ú„ÇDÔ`¢#`¿ÉºÿS‰™ð¶®Ü\ÖÏ9²ñ{­‡´;/#vº9%B1GäÂ¾u*E¬Z÷T·ØìÃ ’>kû®,ïÓPk1$u@)!Õ"g{˜ní*‘œ_ª—`öáWðâ×‹}w"B/ð¾è6þ¡!]æf7A”M çiö&h»ñ Ét–ÊoM¨Œç(u¹×³Æ4gG´†ËÏ°Ï¿îÍØÌôøòkŒºÂNƒ¯t·4vm°ûÐë•ž„€Ë_¶©Ìt‡¥á“Þ.ª5¢+Þ®kSøjõ²r^ñ\DAUp£D€Ì,8üìsÂ!É´Ýˆ†ÒJœ,ÆåMÂ‚VÈ‡j¥ÂT¶Ýæ1Ã-Éo{Oy&„Š`;*âŽy‘PÕÓ¨ýóüö e›üZðç0P)rjÜ(GÁïÉCœ»¿]ð¨caá‚Æ´ƒ|Í]ýýê’z÷…ó•YÍy¼³#™7 šÊÒ€þMöëã¸³GÅ€:…‚_Ø0u±]Öj•£¡÷¢Ë]-Äi5 -HŒÇ^Iœ¹lyÐFÆh¾?A9æ®
Æ©xÍ5Yy’„R’¾Egê
€ýÙCyéH'èêèÃ½Äî·b“’Gnãæœ€`¾$«6¢ê0˜ïCÌólýP8“Äf­EÃÙ½¹Ú_\e¦·B}1íÅ¬ÝãU$YÀî‚ðñþl†¥,š¸§Üeœ æYäI*9Ý°rq~¥ã,t'¼è7æ¤¼ÚNñÜ2f™=¥^4úTÍ (gøE»[¿ZX!B?”lúcmÜ¨Ð)¦]‡|H5üH{\· ZÛÅ5“&2Cu{¼ÝûeÚú	‰\_-@CŽš‚ãhtK8W¾­6\C7uñïÆQê¤‘ˆÆ‚"DÙÔ1ë°@Ú!PjÿC@’ UÛ˜‚Z&‚· p1ê´¨¶´õ_CÂž÷[
Ç—	¼ˆ:bwžá°oÏ‚£P}Ã6~aÀ¾‚–/ÊŽ»ÅHk# LÞg—ÔoÜÅf´ýMõD¢k
÷s[Jwî+)¿´Å|Ìb’ËùTz¾fvs¢Z²5<èæÓ†Cf	ïÅHêÓFþê/	Êf'$ž¯¡ÈE¦:œ%º_PVÞÚÉ¸]õVâ
Av¾hk´Uô| µ¼Ö$Ó>¸Ý]¿ŠpO&eÎ4UôÆMÍƒk5²t©ì6:ÒfFd³bÿ84ÆŽøÃò|}…-€¸1qxÞóäuD¹`2+HñOUƒ·&]ÿÿ)c°Ÿvpê"®©–,îc¾°¼M(ÀF±„ä•»š‰:±çîìÉù+¹s½vB»cï”ë”ÛòU #¦úá—áÂ²<x‘‚	6Y¸
5‰ÑÂ6ø+‹)fCiÏ>gÓsà´àVD¸ jm°:‡î#ïYŒÿÏèÐJ÷æ±ÑöÚÊ½ êvòçCÔÞÞËÒ¢Ì*¡®ÐÁ£;»BÓ;7ý®È‡ë/øÉ¹u²D‘HêiS×žd>ë\)‹[8ëª{œ\ÄA°Ž7o@OrAä{Šišò/9]<=B­¹y}ËÐ¸Ê–Š f³`ì7xàaOïm‹ªV_D„<ßÙGJHGÝK/ì9[‚iLaè/îD²Òï£Pƒ…Å4”zUÐøÉ} B¿)œwÿýkV<ÈfÛÔjúB+Üˆ6«äo’a¡}GÔÚd0»Y|ß©ý+$5%Òò–Í¾ÉŒ6“EdWÓÌr™	$vä€Hðñ~wˆ¸À¾ÑÆ5^ú¹]Åg/ñ#n§Ã"Éç”Èì¼*¼TQG #9ü`y¹{~ÿ¶5]rKº™âóÅ|ë‰ê³läîªÖ¦„³µÅ“J1¡ƒÒûE9fI\*õ–RãiŠiÐô»A‰w¶õ³Ês²õ¯Ö;póf«Æ¦&?s6>G¿q1"”ÿµuÁÍ¾þªv£®ébß²=£)ØF‹èÓLZ›šX·JòbÖã¶Š\98‘?Ÿñ„¬'ÍWÂšâRÌ|ý·%\Ë]J¨çñŒ×ªŸÕ¯ýJ#ÿc´”ä¼D(™þ	0Vxq¿¯GÆWŽ.9Ê„¼Nf¢lúï¨leØ>c÷õ1îÙØ#E™¹!7L¬Š*Œåz´ ýn`<l>%ÆP^è“Êq…”1eS3–õÙºÚô¶<>³ƒ†¡KÓ–W“ig}ÑÕØÒ4Œ.b…ò+Ôç±üw-E¹,;ËãRL	$Ö0pi±Á.ûéœQz.Ã¸6vïš/_…½X›²Þžvµ»s„é"„5ÇÛÚûY¦Ÿ(®ÂÍtó¬j#Í#|ï
jÆÄÓˆÅŸ<yË¶ªgh£ç%Ë_L#±qŸŽÝ;úºFì|c³“„î§c–un€êìZ&å¯Ü,EŸÛva•‡fäŠŠŽqÑlN{‡ç&û”éÇRZ¥¾º[Èàb1Ç&<•¾¿æ|Êë£çRZÔÝÎL—Åµl¦ºÀ4X}œ•j€çbÎ»™º=ßÕ¨Ü•5þÊ÷bŒ<×ôµ[¾Œ‘‹©¿ ”ÃÂnih(åCÉ]›ë®Âg`½f½–Ÿèª~þÀD¿ˆ4’ù±ÛQÎš«Ú®ÀŒ †¶%]ˆí§…š§e\§,çÍWó_ÏÐ_xÿ>%®õGP¤_ÄÐÀÍ§4ë5&Ç”(6Ð›]Ðøgëw»ç¯øAüÈgZ
ÿ®VRñD­@”à´+…å›‘öLN˜fŸ­JS"ˆ¢òµRgÏd`'Ãý-Nî.îûŽ£Þ‹ÇÂ›­ÕXÆ\ÞIÑrÞ¼Bzƒlûü5Æ|0Â¿‚Ï!, Ïã:öãW4x-ìM€VOù¹Ç««}L¾.m,ƒ·è‰NØ_Èn–ñ•JÁ ¤š½ægVG}4“Xh,Ë7+­V<+³¾e]¡©@ŠjÈãÀra ®Ô?Ø,6m\§ÙŽh`I¶ÍO†øZò±§-àYïþi_TN8¥Å$v)+0‚ÝfmaWš¥f5uÑW e>ýÔÀÑûeƒûFž˜ÕN5w¦æ˜£”3ÑP%&¾/ã,àðÈîkîIñB°ß÷°:Éµ&<4³ÔéÊßwÞÉ“×°ªÇ‹_bkPªU›þ°ñkŽmÊØÐv/8Ú§JÏ#q’Â9§ÙÏ9„Š3!ÙwÇ¦Üµ$ƒY8²›¦B»Êzü/×æXöâXÁÆ9sÍ³©L{+b,ÖÔœ=	¦lBåîhPçŒ"VGS•›¿¾•v»~¦,ßöŒ.³’]ˆèBIèÂ{j¹öÚ”S!¼òf£Ù ÕÀÕqâ*é™¬èåÛDÐ@
ñ*Ô´êçreR¯„÷u×_?Ç‹–pË¨Ÿ÷”CH‰ãF”øynH$¸BTf(ø9$-“öa£÷Ü.ðÜÓq@Á­·ÐÔ]DR¨Œ¤‚zÙ†D¢¶#öõÑÝRR.îÑ‘‡5j_•a²TŒR‚=Ôí˜UPkCŽãjeY"k«ÊjGj°í	ñRèeÆí¢.©ðz;MqqÊ_mÕ·•Üz&v#8ÔKvèc¥w)r„ìà[7g‘Üº"Ö˜SoûTÉ=£ÛÜ#¤ÊîB¶²‰+7â*UU *ÌHu‡vj±×¥jÍ–ÏœéxQéÿ7÷ÝÝ%G½“M(›(œ[^¢Á=“[ÿ@¬²!ž¹ŒuÏþmêzÑÈ%ËAkÑØÛ©ì8@¦ü‚ÄO…ë€üã ¸Oì(ØÇ,?+Íê¬Š†~ó$A¯Ëù¿£ëm®•ÔÉWïç–Î CV»Yš‰ZXÂ“Õ½K-¯¨o4~Ö@tnŸVá@8S7ä(ÛËH‡åÊ…¢ý2q"ü5m6ã¤á 8Vèø±oY9«`ÀÚÚ¿[5Æ(êS?ú¥OÔˆý[Ðû›Ê¹œªÏ^’šIÓHÞÖ2eš4hn&ýqÿJ»^IcNi#’ƒã6Š¾ë*8ojä~èåÚaPÐizpÒÒ÷‡$ õ2˜~›#­T,`ï „u:ÕG…£¬pÂ;˜Ð›Ãº0°ÂFÙ`—ãoêšÆ*	’ñÅ¡qÐÄÅ+áfE.š˜3Ÿ§÷ u.`'â¹äŠ…Êë–ÏyXÏ\›ÒÅR}>ho.:4;G½)hx%W¢éÉå]ÜrväÄ¦"ÃÅÇÝ!—V° àã6h£'P±¼[0@wCsT#ïKç_P¸˜k÷]ÞRNÿÂí°g2¬‚êríûÑÕÅ¨TH™._-¦|18ë–a±äŒ˜8³©NórŽ‘–„8[†XùõÏbžWxç¶×¹ÓWÞ§˜kþ©Ê¾Ü+jN‘Ú”I®ž,W|‚•ÌsTªEVÇ-\®>Š‰±Äb‚qdÿ_¡6R	Ô§ &›âv£Už|‰]’a¿ W«óT98›k£Ì‹KXÂB´ò-¼Lãæƒ]¥æŸÙ’Å]›L @T.ù„V¿^L¡x1ÅðPž?~:ªß[kí-Ë©Â²ûßMÒûSrçô&ÿàÑeícRMÞe²yCCáÍn†ƒ£èÞÝl*òŸï‹xž)(eb|â)°öU¨.”ß+=EnàÌ·MÈ¿ôB5ƒN-[X×ëû¿Š:}mÞ€ Ž†KzbwHévšøòÇƒÖMÆ§téÜ÷òßE©O%wüIõd%ž?©ËÚ³´ò%nÇt2òY!Ñsb0ÿþ[ŠÔŠIEx)˜üØÄ¥>þà™‹”pÂ½ŸP±ïŸKö§-¿U8ú–ç‡aú[­â•o 
¯XõO¬Ðõß®j·pg³[&°Æt'íÊÒ¥Ù›&	ÕÂ)ŠÌx Ÿ2òd>îìýK-¤œÄ‘x¿ñÙ‘#J€ešÄÝ,|P_uÙ,cSÍiÕ³·´ßÛ9:šˆì}”DëÔÞÌ"4œª|ö´ÞEfÂã‡ç[¼ó‚ÌŒ#¡Zwé+­ÞÉíb%íˆ+ñÜ4	Îøe:Ôvº€ò0¼RàôFmÓ¸•‹GD®‘&s£ÓAÉ²S×/ŠOy“÷8	èµ½¸ÑEæá,´dDÄëüuÉ’Y‰÷¢”´Ê‡‚|
%¨q˜(½QÈ³FÀ÷&ÍeÐñ<q«¶Z‚‚Ì9¹!N]™¯õíAA#Éz'2ÙÜ´ú{VÅ7R¶ B.*ìJ]@áÛÆLb/gëVþ¤UôãÖ­WnÛhI0{Ä×ýšFh¸"çˆ(4– YT¿M¯ÀeÎ¹•3N•úµ3—ò„Kì1Ã6ž<†s‚æ:Q%ôÌü4“?¾knâb¾BBamXëC$ýÁÉ›–™˜nRâŠèö‹PÛÌ Ÿàn^ÜJ@ájWgÕ½µèîahžé‰êÜºÚxA–Æò<=sîlQÙæ(C×ŸÊ<Â°m¹ZðGì.›“»QU¼êìs0a•¤WöªÉIy'°ñ·6I¬$x,e	oa?ïy7??úŠÕh¦Ôìlìž”œíLä¨xåê6ÁÂ‘FL´{W»”î¦6^ùbKÄ™I¹Mc‰6 @i´›G\M]oô‰„U€œ‡7ìA-Ô}Ó>tZ¼Ô0÷z>ŽP²¯Ñxƒ·›%§Ü^7‚ÒÖl	ý¢L³ìÅ¦g×tøžÎkÜv–T0¥JrßnEÇG‹UÍ£†ÑS¬ÐØ&·é	­@ :ïªbó>”â‡5×ÎRnaÓÚêóÛŽ
l)J=Þpód´§D4?·¬Ò„9Ù†›k¤~=¢!@Jsÿ­iÒ1áÂ$™Z—½&N8
5Ø•`jzå+0pˆØ<Rîº€¨Ø+aƒWLòòcþG°”R_OKÁogReºÓ„ü½¢”Òð‡ÕNÔ8a<?7†æß%‚X•æ]E¸Òe[x“EªJM™òµïŸE{s€Ÿ¹>_ÚéSùa±DŒ"0°íÄûº‡P±CíZŒÌÛpøt6„IíYäðÚ¥Õm°Íšâ2P-ÅÆÀF%Ú
Tò¯û¼q<=Û÷¢ÿ#ß [Ñˆ²pùZú›‰•À»Oµù•ó'C·q R”Þ‹SÁÈü®-Þ7‚f€Ä#óº*tàá×èV™„à-lN•õ‰óžá0ˆÞBñt^Å-ræ	þî‰ÿïAÍl¾ ;Ï §¾:…à‡Ñ†r™ß‰[ˆi=³‚xO·v¾vBœ€ŽÄ H!]ÿ#ÆƒÜÓ`ZxS©êWlgZÍJ±»É”CpÏÓ.HÞk$·÷M&¬½oíq¢§ŸVâa->Ì—¬0Â”‘×ÉºJ07ƒªm
±ï.­êìÃsh³`€¯¡JJì+J¬Þ>¼j¨PeëK zxZ¿rï¸Ôòfíæó„¶“Ôf™Oó‚í°bÖœáð†«F#«Ç\ÁDZãØRxä\eA†8S…Z)öÛ»MtëŒÚ	Ü¥ÿ<8“¯®ƒµ-µ1öŽ|þag~KNriôçÍéá$Ï˜´!„yêbÅS¬>åRpuÞú8Qú¢"œÇXˆ/VJœ¹ò‘t¸÷˜Áõ[š{IKaÿÒ÷0ÅHïb„Y«•ÎûE*ŒO&öÿë@¢Æ¢ƒ ¸Îæ@ÑÌïõÁ«‹dwÄšú¯pÐ×Š´‰#wö¨·|ØÝÐt(«5‚¨S
Ç1†ënÕxwc“´CÝ·îZ	¬ý'ÚhjîôË“uh¯|Êë†–¿g@é«+¥ÞU”¤9mp÷å^&?MFÚlönÒ[•\ÝçfQ+ôx4Õ²—À¼@ÐÞ‡z¿?h.Ÿ¤‚_ñ²ê×»A%u‹Û§xùda³”OõŽNÒK xhS“ï6:Bþô)ñ+Ü]O«ž@åÍ+_ÂI4Ûô³«^AáhdIê9?Ìœ•Ãh*§ˆÍ1ªÌDŸË$í_Yw¡ÿwƒ`ÆÛG·¿°p
¶¤ó(„ÿC¹?(£îmÚÓ²…v±H{íò11°³9Éß½ÅZ'.nŽì”{¸laýD›òåIÐS±åfhÚ‹íõšKÚ¹ØZÎÉ…Û­"œÁ9O¯“+	MÙo‡¹3íB_%Ð-Õ¨bkî(tkŠxá‘7P3…9L¢ËF©ÈÇF'^R&\60õÔÅ —ÿ‡Âd®N(‚*È·G± H^æzf2êÜsF(d6_-ÎvMh`
êvF3ëÈ¬§«ó“É†&æÓc _¹RØµ”©•„h[QRcúäÛ¿öpH7÷£	O•Ðü”–=ï¢0š-1ÁDø!º×¿žüàa\ç=Bï
[6õCóÁÐì6³•gO3¾ô6Á;Ú¸Ö¡ú@ß*öþ†”>Aâç}Š]±ÓŽM?»ZßÒBÆÜ‡¼Á¹ð#§Y@6É‡ƒ}vþ×j9‡´|6ÊÐú#ûåéGýËÔXócyCÜ£€¥w“—f´ÄÁ&B÷(Xo¡iÑHÿƒÕZLxæò`\Ð[ìÖ·*épËj5>M¡V7úƒðÞ³6jùÎ˜åîÏ„;€ð@€Úž®¤HîX…í)$ÌZ4~¦èY*²‡¡ÉS6‡F¦½; +ñsfÌiÏ¨­ûû€@uXfH©[< ¦–±_\J—8?}a‡Æþ&Næ7ýŠ‘ØØ¯åÚxß	_€‘|×]ã4ï«¼Ÿ>`µ«õðzZþr%Ñ8Ê ø™$@RJˆŸŽå.rÁédoŸu=~½ŠMë96Œc¶LáÂ;spN³–Øª£‘¼ÞÓ7Züþ­›ÓçŒu¿ò”ý€sZªq4{?]ÞS¡…’Ç1ÚjlýÀtÐüÜÿY Sÿ¾l‚ùGê@:ªà¼ƒˆN«ù êfv5H»C¢:îËHœçé¥2â°í1Nø{™“]ž/BE¶óÃIUy÷wÃ'­0²ÎAÒWdNòóØ£rY½ž*ð7aÃS‹©2Wb½¾h¿\Æ=%ãìÞj±•¢vÁùßíz«ÞÅK?(¬J7ÒŸž´×²%›Ì‘ßló¿jŸœHivÜNNçX3€Äoî4VýZaßh&P¹”0÷ø	ú]17g{8C”²i	žV)‚æÀ’:î>S–	ÜØ²¹:ì&¹ì¿·Ù`9|î¥u
•§$e¨›¾2g™Ò§…ÁÕiö³í0ô­úí4xKbQëXuÛPTVñT¾în‹qÖÁXðYd®¸mÖ,¤ÄbR¹;eAâKŒ€ÒSBþÈs3×èoþÄÎ…zÜå7ÐÙÄ[‘ÅÈOíqgk‹–´ÌÌsða-—ŠhÀOõÖ„Òs¯ÂàCTo0¿®oåŽúÑe,òYå=$ÀÍ‰·™ºX\jü)>¢ö£ŒOÕ½©_U	dîMµ);=#Á[Ú¢œ`8ˆïï.ÞÑš`ÀIÎ—ž,ûŸØ»6úMÆ7ò/â¢r#§mÐû	‰
¥ñh²Þ”9‘§`yÚÃŠ#Áz²“”*ÍõåËBÐ¤[”Nï±^
§úcˆ1XT²ÍHD„Œ¼	f°–Cà(ãsÙè@	S½ÿÊöHæÙ÷¿Ìœ­f¬Ù@ˆ­¦$¬á\Ý¸R½e Z¿“ê€ˆ¿Ö‚(Äs^x~÷Ù·ð¸ê÷ílx]i¼€Èa­þ³é¡t¢É[Ðož	Ûw{-Ñ=Y4µ¿vÃªK…óÃPxFÌúºj¼:nËFiw5?›”:U7ÖPF`žŽ'CÕÑã·AŽn!O¹µöb¿ðÎZŸ‹ð Hûê_Rö,lïl(k¤Äxxž¶ÈþÉîyá$÷Í¶:‘úG¦— ¯ûeg8Ú“>o	ÃÐÑ§æIã%•£Mz¿v0lŒÎÒ[«"g®"·!/8±ôˆc¡Š[ƒ¿BO›LŒmÛX‘-ÍþUa­Û Pdº¡'E?:çàÕ2G¸0'i>n¼:–UR²¥ùx¶àošiãÛ|aŽ¯ÌÞP*¼\ÿÎÀY¶Á‹[ÿ9i´"XJ…1)‡Þ*,ÛPû„ð8Ç>D×iªv¾Ô‘Ä×*Z×Cí!´·7½ƒ›¼@Õ
£ëééå¾Fuž1…8j(„ Hh´j±ÒHÃUÊ"AY-É.ˆq4ÇYmO}m˜?KTðª{Ä5.| /š è¯‘OþTlvÈ2“·%ÅÜ”¼¤±Ûaî÷7î~Å¥L:{IŸÀþ˜§ŠgÑ›NÒËgÆÜžmÀòÖ€Ý•ËCiá¼düdO¯–ë[úÐxzïþ­·TDÚðÛ5Mþ]nD|œ0~£9fõàgÉ5¿k L[5.#¡É‰o}—

_r ß?®ÜbzYç­î‰ÈèðÎO.eE*Dˆ
0½oh¡PãaÆÃ?šôþ¡c“ Q“k1)µ1)wzm1R…¢‹êîd¾Î°º_°WO«ªq·YpP™:úÎè(;RþhH@9žÎ7çÛÆf‡4¥–FÒÛ¡©}L3Ë–zÁ¹Ìô¯ÜQ3ò´¢±>àæ6ñ]¼ÂŽ‚zCº¯“í¤gÓüÍ¤BÅÑ<T]Ã^½‹="Ù$íI›¤â¬
ÔjØë½[QºÕ4ÅoCu£ž/1¯‹…)‰µ¸ÃÁ¬Œ×<@í­î,º£ÿO3ìÓ®™,Ž6W¥—XQ¯õñæ ø¿w•uÜ-z\q~qïª#ê÷bzè…¯ò¶kvßGT/0aˆdˆÖiwºµ¦y~|e÷xÔ¡Z³¯ûjÅÕ-•CW…$#”ÄFò%†—Ä3yß\C„T6(§‰:1‡ŽIËŸ£‚ßÄÅ*n“wÀ}]£
ÌJ7T1£S¤oö¿DâŠãË\Ø§¹ÛŠ1!÷øNõ&	1`Ob‡NÜÞNæ„<ö!„Ì“,ˆßÂ}YL9iÝwJIq¯~9tþVåG¢n&³{ËlwSÎo@‹‘8‡W¾˜.p1áÌ.‚„ºìÔØ? ¸XŸ ×¤ÄAïÉúYØhLŸ7î^ $G™éx@‹™ÃbQb‘ýüŸ×ƒs3 AÈ¤·5zrc˜PàÚ#\èWm)ÖèÄsùãù[g8_ÀY˜˜ã\%hK‘ U•“×«ÌŽÔ3€ÞJ&5rûLšçÜcÄù–Ìm®§ ŸJƒždµ-Ø»Óyk?/ŸøÿÈKÊqß’üc\ñ&Dü†sa1ð|XÁ‘HþRÌòîÀE+ú”çÚDÜ¤ø€X&Ø¨æOÞš]°*ÑnTVMïÜS
v`•¤[b¤aF_gÑó¥t•ôÖñÔ® /±µM½É[ˆ[F%	ÕRnEmÐJNéžÿWg*ð=°·@|ò·[}>EjµÙm^–ýê…{ßŸà¹°ªfÏ#^œçi¨Óe.ûÙHR±[Hp“•\Ž<ô½¹Ñÿ=uíc­GêÙA ³ÉøëÈ=µIôE¹õñ5z±-°3t²8Õtqß¨Îý÷ç4õ«Çu¯‰—WõáÕtÎ€™¤ä»vqZ: ‡Û‹ÔÃfÝîüëòÜ=7W°QKGAäì°¼Gë0ÁIlÉÃÌ –Q|BÜTERy/\‰ýžEô×TËàî3|žÌãÿN-k„'‘nhÏoÍ˜´µ¸NA5?°nUñâºMVÓžÌ{=Ÿ4RE †!ÁU­÷+rç®ù‰;[JU¶d“ÀÊ+µö'øs}ô	ÂwØûo9á‰H2ÎÔèÕ&3pDé‰Ä›»gbÁÚæª©Ã-Í ÚŽ±þœ*T*nÃ'ªúŽG¼OÉ#3©ÜÝÿÁ²Âìw¼šŠß½‘¤öóBˆ
à’ìY"æ¶Mô5q6ª†ìAM³¦/*CÖ=ªýÈxðð{pÐ.öÍ\}ƒ(æš–»EØ†æi[?æ†ï-šcD)­É” •“÷ÈY/é›Ïk~%=~ÈuŠÊ7ìn-ñS“Ô£cg!ªdºßÂŒßbi°íÉôop	þ8?œð¡q¡y#ÊÞgá€¿åI*ÂÐÞ²[é‘kž¡ÏÍEËP»E°¬<iWÆ­‰ìObIQlØ¤7xj	PŠ$ÌÜó‰àfà9&Îu¿ü&t->žü³õŠo%ópÜdQn…ib²¹;šé¯`ïžŠA÷e3xjå>´‡ñ¯A8×„¼ü5‚×—3Ú;ó$“	b´ð‡[È_Gæô_Fg9]i7Ô¡8 K¡lŽ4ÿÇ×“$ZA™`q2m	+ ù‡D%—_€fÛ”{õ6$p¬×“ë1VËs€·Z™žg°Ý.õ‡¯DW—‰wF	‹ª·Œ„^†)ä”9¶.Q%×¬Œ¡Ñ<påéw²àuÇŒ·ràX>îØp¾
X@BÁ	4Þb]]ªCŒ:-ºËR¬¼0gÜS‘‚ùr5ðxìúAGÍB&Ïí©¡žf¨ÃìywœÑÈŸáüJÀìÑÇOè²çºf*ØÓÞYÅê$C8®1ì}øØÈ +g³EÕ®Ña_4<ÎªQø»‡˜µ¡öC™\(qð-Lêhãg{~)›u©W¤_»^Äl‡$üŒ•}c{ŽjtÏ£7¹Èiµ;î ^Ú!ý'k¾>XzØRkõ®ÑE"1ïµ~d‘yÆÛ(MŽ”Ë\Î2%i„ã÷:î%°VLÿzeï6~‰âÌJU}_R¾µ£Eÿ/”éª,Pc›mœ¬‚ÉÆ•„~;ÔòV$ïÓì4xm„@ ”T‘Ž¨­$~ÕuLXÉàR"bÈj¤Aw5ÉŸ=Fµ6æ>.8|©ôéÑxªŒ€«!´\ÐÇKš‚òUW¶®@†B'ø|îöUßnŸk0²þc6ðŽÅBºÊtD’¨îê‚­eÇXº«ï¥0¤ èHÈƒö–wôtŠœ¬”[Ê<Þàœ~\<S8©vuw|bóMð•®fÄþ²3qóÍµ wp&\ÖUÎ«˜)!†…*ÀókW;2/fùøáŽ¸R„‚àÉ'|zÔ?£ÕùÈ^(Á¥×G…þ4›V˜ï«®.åxýýBæ¶üaX—¼
ñ:Î½Q¡âæ|¦NM€"	šÉ‘/õ,‘ë_SåØ£W+/WÒûºfÚfaÔ{¯ª‹K0Lå­	6ó¨GÓI÷Âôñ\T˜Ú97 ÷‚ÐÐðMÜ=Á^¡UxnÉ;¸àý·Ûh¤ –\–ìgª˜ãßq¢Q¹f”qÂè¸¯Ëñ§í¸‹m¨Þ¿«à/ÞÃr	Ì8–$["8°ð’X´PeÛC*Í!þwôJDD¥mÔÛ4öÖLSyÔ 9ÈH’“YuæÃ¦Pþ°—M3ž÷1Å©™|qx-›Ê8JÁO4"ÓF+„±'ÈÅw–ý+¯ŸMxTa¤­IaeMHG¤h~›fÙÁMß:F§é8Hë¬µ”þðÑ³× ÒÏî=é†ð‘ ÉÀp#<vSÀº§tˆ*{»Ô
¬Í>nN:3—²ÐÇí ; 4ÅÛØ~9¬Ñ×ÇNâ/gV;B×FžÃÐvì`pÉÊëµö=n\òº oÓ®Øö›?Þ¤Þ0Ä^ÉÜ;ÝôãJ,T›So ƒò~>ˆ­‡\}¿tt¢Eîë9êú„]%£Ër]‚ÍA¿›˜â¢ØòëbÇjŽ·©…Pü{ß	¢Nts­És}Í¡Ø¨4ƒh³È;
Çx:Ÿƒ;À}wç˜>“×ü–õ§*Ôl-7ìêhN?N¬å¹ç¬’X2·O%d’ÕœW^ÆeCìôŽ¼ôSu¨(`s:NÚÞ¦|à™Ÿ+Ñç°/O!¨¹Æ§?Î $É—ìˆJ½Lñ‹õÍÚHÁ…è¯q˜Ðô·eŸ¿‹¹Šù	$ Z*>n2ù
McÉJÆŒ2­Ë$Ï á[CI²Ê¿ÆÑWš…yJp?äÑ!$Ã"iœQÑƒ–$£CUŒHæÌÞ®	nâÖÅ–¸íq¬•hT°¬Zé7Zõƒf&Iû³cÈÀ0<ˆ‰Aüácà^5˜‘×Üa‚Q2síÞ*¨âOÃWžÅ}êéÇqLÎåJ«¾„t¢´©à§åZ¶Ë‹Éã&d
J!¼ØœÒ™ŠP„#¿œ36Ãª“±í
7žjñjÅBó£ÄÁöAŒ]pÐÍSPØS 7Ã%±¦·òJýJÌ8	Â*à~ÒÐë;<Ž .\ Ç­Š‘e3‹.zÒì;o¹_Èäª§ç §Hž›ùhÖõ9ÆF>wºhs!¶3£F-ÇN¸b 4<¹ÛºŽ–éºÓk™I½I—²šÉçóøÏ’H´¬K°—ÜÍ +=–ŒÈHñZº²úPOÁ
ýyi‹è{8¡òeç}NñŠì©Áƒ¬;Á‰º}TßÌ’ßš²²ÙGÅ"ºee­ã+þ·7å¨à¡SAš¯HÝ-}‚)úF=Ë?4Õi¾Ï™äA‡–c´p5OªÑúJ7ŠK£¤;»)¡?¶ÕeRiêhåZüõG.Û/r©½Xå¦ û45v!÷ˆÖFNíýi/™ÿcñ¹=§'êûá”¿'‹Ï¢U·~X†ÏE*e}+vOVè8È‚lÞÝÀïE‘•ü´¼Ú¬}'K$Ñ@Øž)ÃäÎ
’ÀÎeÌîHl}4ÞU/žêOÙ16ß¼ñ›cíå€šÃ‹ ^†ßë8Ï8Ð&NÊ?ì~IëÞ=fÅ„O¡ð€ÿà•Q{)2ŽøØ}kª<0ÚHÛ›M7E+cnLëïÓ ei6°æO;šD›Õ´«ˆOmÿ÷^~Ê+‡õ–é2|tl(§/Âºð#WP6&â¹þ‹Ä›áíµ½Õ±øý©”±‰‡ñ;á8…áO¤ÉÙ©'àQyÓ|]÷Àñ=¨†Ü‡Ùtüx¿(t’Ö—ûäD¥DxO#G×8h/}¡äÕû«±á‰w°,‘_ÒSÓiå^ª²3ÙÍŽQ=áwurÃ{ñUÞÔåÞÆÀÊø¹TÝ/¦Ç )›¬_ }v*‘¦AâµdÐGü£T	/	sý©Ä¨p1L¤Èç>!5`ê@½·Ñ1T­Š÷¦773úÿ@<ùx‹0}é”º‰|œNŽ †R(‰IN4õ^¶î‘RF+Cfþ¹JÌØK0»÷,ã@n^Ìû Ó0H'§@öË™¦¶¥dÝòÞÄi ÊTyb<;ó¢nÌÉÂ¦	ªÀž¡²òjÌ—ý¿;ÈË.6¯Åð
äusGž”§SŒ%öo}”wr8Ä|¡«dõ®§¨´‘-Ó¥ø–‡r©Þ‘Lv‡”Õ$ª€ù5ò¸¼7á’Vê…Òx”71Á@¿øžµ—£Èî>³_½«9óJ±'^þÚóUv~ÕÔVA÷¯Kº²"ªK…u#Æ€Éq†õØ|ÊSK´H›Ê„} Gí$®TÙÝ.qóÂ©û©dò):ºP“	^û`lpNóá7‰æéõÅˆ&ÏÚècî“ô{«QTÎ“ª#«A5Ý^n‰Ügå©°‰ì7ìLµéÌ!¢èäTmRÍZùý‘”öÖOËšø¸Šâs±ãrM>Aà êR•g‰ ÅÊaóÀÆ^¼aúÊiÏÒÉhJÄk²]Â~ü˜y ¤*yÈüþÿDj@Ãú1¶IhÇ(WcjŠ8âe@³Á±4„çiÄåò'ao›ë8¯üäˆü…*Öw™úƒÃYËæŒšõ›pE“íÓÙ²bÉV°×üÖæEÒnÃëQÆU0-t/œƒ´¤X¶St’- b)™ Y¸ƒÂg.ƒØ«“˜¬ûTI~!°#·Ñ)dºGiLÚl«éå´Ý”ÇŽ¾‘Idx‡s{’º
Š/cñ°df£^>v‡Z8óbgÖÃs•[O´{îÊò«at8BúhéŽÜánÏta©P+]PNé·ë€-gäs`]¼‰ÒöµŒk‰^Š¿‰4bþ+…#eÃDóuÐ¶­þI<þ¢Dö×X°!WMXÐ*ÝåF+þB!ngaâ²ÿCHÄÙítu!Â¼Sbvì”³‘°8o¸¤=éÖšAšíNMNƒ»0àB®":%‹Cò-H TÑ§l©ö7˜sÖ‹¼0÷§4PHAõI¼‘áS¾ö3Mgx5Í|5îtLUÀ*íñËÞdmßîÊ«wÂì×Í8Q¹mÚ_m8‚ê¥m<8
n;Ô(¿ÛÁÂjÓIýÒÕFËðÌ/z›u%èÙ…nUƒ08ç‡…‰«;G™ŠSaGd6<qnzÒß†ˆÍé™‹ƒ+°4µ”&I1êL	-Ïò½=­ÅáìÖZ?•¥Âš€
ïÞ…Œå8ür[2Fãeü«VRTß'CÙ¬·Z.ª½ÝSdÎÀ²ßoŠ_ *Œ›c*¾ú.á±V‹À«Ÿ’ðôTA5ü0ã/7€ÃZÏx?l•Jà3ôiçèlû¸'ÜR<¹ŠËÃ†VAš]¨H@Þ0Êçz„Ië%	µ«…Xê8*i½‹ ¨?F$aro-LÊçzÂG~äÑÔ¥Áx|“8ñÖ)ÆeÔ²f–ê*w´e)SÚƒ×#nŠ@Ì¬ø®Vï„?Àbï…y®æðJ"¹ÛkÓàç±’;BÈxjœÇhT …˜È«”%õæ7’ƒ"OÅAÂ"Â™¢äT¦èäÂ5zå@qRLÓç³²)²Jº`=i“P CU8’ûœV”˜<\æ!ÂïÝßu_u:þ³7ßƒQðÅÐÙdØÊ¿³Ðºú|.«ßŒ¨NØÇaÝ¦ìð<—ài§º‘—çÏ-z’|¥í¨ªtÃ=™<3–\6r¾žêJì¶Ñ@9q…!ö…“»\ê™‚õ(ù±µ•qàcHê,6(¦HPÿðZÉ>ÕÌØã6ëÌç0)ŽvÀ¼"–gm_é¥ƒ,¥Üô=1À‚.]Á/\8œÃÄ5Þ~T GU9:ñ+ÓøÔº2$ÖhI‹oP)Ö íÂÃ-.™+r* tŒÊ85lšWÅš w¤ø¤«áœØ‚¯Åù~¤müBmÉw3Lò©Ð¯†×ø/5`}Ù.l!^|»WÁWÛ"„ÿy•úÙÐIúÏ<¹Åàg&P^iÄI¾7€…|<‡¼ƒû^ãäù'ùÏ•*K¬®Í0ËãÐ„§ÉÁë‹Œ£¤Žy•Uû<^ùo»ÍùºNmCçÒ—s'—µD¶7_N$ï´xÄ§ä\ÏN UU‘uxÛÐ·±È£1é¾£»˜³¢Tƒ¾R÷‰QûY¶o­¤=ÏBÿ’æ§ÚÔŽŽÕ8m»C±òY:­×›Ž• ¸LÈÕgãkFS!U,‰•ŠqÝ`øÆÅ6‹ÉøÑI1À(+Kavê*Ël{€ÿÙ.æaÃ•8îô´7åª;Sq—í’p?«âTRXs‘ íô8UKœ&l5p¸:šàR¼KBû.›¸YP Ùà·&!Ã4Þ7)äÔ¦ÀŸå9Òà^ 'Ÿ‚‰.Ö°ð¼ñÒ’¦Ð•^tá¿a¨Tlþ 5Tça¼á]wÜUÒˆ“ƒ½Â”)ÐÍ…ü/ Ð›GÛëóõØ79¼èÌÇmE¢lzO¶”™ÆÂÙc”ðuÝ5ƒ‹–Ê$Ó{}B–^,Û'™êh?™âÝökãm9ùBE¢ŠøoKEõþ|V7Ú<Ô–=â Ç\1ÔG©¶í¥³‘f8Gy—.6½JOÒM,gn8¤Vþx ²ÚC6Â|ÌQÆ¬/.¿à¢D‰ioÜ(¤ŒÌVzW‡@QýM“­Ñ™ˆÀ$Z1TjÀôÎ®L×½¥5>BJH«ÑT”í)WÛ§O»Äª?Óäï+µßÍ5{Xï'¼\{˜ÔœÑô–è²á›1
êê€hñ"Ïhk¼­ØúPYÿ©†÷tØo°JÀ6ë%V…ë'cu°üÖ•³j-Ñx1­X›ÝÖß…çÃå®Þ&q!þðÏINækjýR^€!á3©K%ñ³[X©YÖÕ·¹vÄy³ñwcÌ3ó:"ñF×
‹Ñ°ÄËR£Ú´È¯ã$ˆ‹ªB­™<L$f¤ht™ŸÚõ”ï¶7U?«àÑObé%úf¡ÏÓªþ–·ª‰öûÝÀ284›Ó¡øQzX0õS2YAÑôsä‘ýýÈ?‘HÈµ¶gW}¬²8²pü4#°ªgmÀŽeþPtëŽ®à„ú-—á¥£;ÞÃgøè5w3K°Q^ìF=óy–X¢žÉzêfÙvoÇC -YtE ,“:7úÑ¾ÆaÌ}Ãè¹žXž¯QÌ³n>ß Ï¾b^q,)ÃÞq]]›Ä Hõøÿ€OÎtšsdó½”!âðêLWðŒ-{ÀÕ	úÓã•nS¦nÔª˜CòàƒÖ/Ý‡*"ï‰Á:¥-zÝ¼²AŒ¡SzŸ„TÇô<^æ®¼b6	 “P´½Ðb&ªtûƒˆËõª	'î6r™ÌU¿ÇÄ]6Ú;Ò|[£cX|uU¸Aoƒ¿¶çiwöœL{É‚cÿ®Øûh+5!æ©3!Ÿ|IxO¹ò¸Bc/‚ýŽ[î9œî¨ëýhì»À_¢¢@ca™õ]€PƒÍ+æšÉÐ[*	dØ@Ú„ÃêTáùuE¶4^&‘Hà›¹[óô½4fÉ0+‡žJqýÞÔÕõãó¾åm–€z£`@VÅ­×£6—f-(ÂŠÃwJì6[uA¶Gy“ì¬^CÓC·Â{—ÝñË#ªE®Î·©—ü¥CM&3r+™9HMg¨°žá™§Se	px°Œ}~Ñ˜ÐçYA_Hçáý¦\r‰¼
›¤ØNb»[ù~RE½caþ,+Šòm|óK61W0zÂõ8­¨`‚%±²˜ýÞ{ËÐMØ%‡ÜÖ*L¶!U÷ŒÏnüºy¤8)°|B«M£{¼<¸kŒJ² PÅ¡l{I‘V—SìGIô®ãƒ	ºQt~ñzøƒ…ÊšuÀ­mˆÔa«ta‘_V×î˜ÛÐ'–IÿDñî†K %™ùìˆÂycœ¬{œ³ÅVBM¬¯òèõ08—¦6ÛÅ•ž_…±s¿ ŠÃìó¸TŸÃ°‚gÁv&œÚñs_WKûý”£ŠQO;ÌBžCÅJü/î¾yNÉòÏx¤¦1£¼Þ(ÌxpÖ+gâ¶¹ûú9Qÿòh(ñ¯ÂÈ0ÜÁQí>gk.ÌM!Lœ©¸jY!@Žß¥†1Î¡½›¬M"ì‘ÉWlƒSNX¬Ð–‹™^‡°¾p÷ïòaÛñô®’‰n¥l’=y•Ìua³M«‹WÀF¾
§n,Ìi¦åßøàe«Í	n˜Þ7‚ÆJÚÈ§@Ù`¸‹7m'ö:ãœTEÐÍ¼+uAI¿áfLyf*Ñ'Òð²¹óÅC•¬Ož3â/ìýŸJäš­„2u3«ŽÖ·PYË¬„&\u?óFöéS8rß¢‡Ð`YvâCyhbW_`$zÇÁ´Q}Ã>\ƒç=úëbÝáå­Db”•ÃÔpã3á¹)ô5éžÈÊg¯´7.(/‰·Vt0©c¨ð§š¾#Ú½62©5|ÉË+Ž,ïö¥º¼ÃÜXáDc€ ¿ °«2ñ2[òÙpF•[¹S†_`Åé÷èî¼Ú:Ww9<Ü^=¥¨CúŸ é|'Eð‹ÿ,±P\:''Â½"úz1þP¥|Fî
³Ï|Ìƒ¿–IÒZÐ×-êÁ£ØwO&æt0²t4uYO¦”C†Všú°är¦ŒBü|W}Ù³í‹¡µ;µ¸Òh‡=íZ†WóÏ\€‹mµ78{8à8ï+Á?¬Ö¦“?Ç}1
N7&r´=Ç´‘B–úÌ™6F"TÀTh‰Gâý¶Q@²*í{4vöÇi£€×W|`µ‡f)©õâ”=AªìÝ79T2)¾W´ÍMï†å%…œÌ‹rçwË“›ÐQ«SŸíoÅDÉdŠ BÈyc?¯óÓ‚…œ¬Èˆ|ÈAg©–6‹Çæ$TP¼C)JpWÿÎ¹s©ä¸C ÓDIº–²qdw¶øQV=ÊVLðC)mN>Är¥<qýc™F6ŒáÍmdüŸ¯Ä3ŠW!w›‰ùK3Úœ‘„p"íÈÏIž„çÁ†@>£gV­î3êubk2Ì…Û(²„ˆ™”Å‡õ¶L¤/ƒì¦0ž)¡ô`<‰ÝëŠíXd0—õà­¨ž4Äˆ¯Ð(„±8Zý†ZhG-âÎ"íÌuw¤lòŽ¿úõ'•þOF¼ø„Õ^˜dKçøgŽÄwÉäÆ' &S,PÁöKhP6—,œ°ùèk8hT—^aß±BV¡©Îî÷æ½‹ä¹¹“>ö¡CýQ2ý pJ?kÏ("uððºLÿÑRsÔË~!çîj/d\±iÝGA“O+6+‹Úež7›;e½YUlZ.òf¸ƒ| ApÞwTåu2Ù–wi°àI×úX”ÿG« Jpçd-»Ú¬ÀÏÑBÂõ0Á1¡1•?ˆ÷§Ï‡I’¦¸LX‘ÁÚÅBûLŠñÏ‚x­¬F3¸½\ÁHü(qOeççÝ}W^ŽÄXN¶Ñ©÷¦‰J­jÃÃ!;@ur½rãí™’è«éî9c®¯øª–nÔ{ß4ñÇÅþÆtS•—ù7ý]vsGÏ	ýp;”§†ÅÅ§’áo)É‹vc)+ÜÚ:‚`»¯OÿÖ¼¥×Æ—.ù1¦B;Ør×íï¼ð!1Ôsr@cµDs›Yy”5äûp‹Öœ÷!šž¥ —Î½š¾cîÎ8Ÿ‰ÜÆÇƒŽ)Ä 1Eo±h-bÒ„I3l:]òÀ{ÛE0Û­öÞ:üFsªqØ÷ÀáÚ0Óúh€Œ†¿ªXwí®ˆýsÔuj·®º‹ãæ¬éÇi1qÊWü‡«¯u	FN3îs«+©£4Ç0q|ÒeßÔ´ÆîºINâÄ4ûÜá§XkQ ‰3e;&‚ì)åÇŠ¥;Œšyc‘Fà5]->‰/%îS˜N8úx7¦§”åŸÓA­]"ÀwíÎŒ·²®c º¼ÿÀ#›âè˜gº “h\mÀÕE„ù­qÙò™ÿ²+ Ÿ&›Þ:ÆúI‰4–ð«¡@>¯t`ÓßÃí\¼á!Ie}ëÙíŽÎüj^Ä{
.¶=AìSâwÎ¿&&u’Sý±—µj‘vd%Up"³XV=€ò¤Ž›bB$³‡ÎàN€ô@ŠþÝšt†Kîöun'“L(°µ?¯B%¶Aàk^€ÕnÙ²Jþ•½FZV§â°Üh¨²¨8ìQ­RÆÕZõÕaÃ•½H¡:Œe%Lt#C~¾vxÊ¶Èå:«=$©¥CÛ;]Ï¾@ílýPÌ@GÔiQ]COü4C½ì	AóJãÉûg÷µŠÚÏ'ñÓî8÷ä—­ÙÕ´oþ·´²±p³JfJs6aX}ººø±¬W¼¶I¤5Sèýq„§þé/´îŽ7ÅFÍÓÁ.Vy–fY#ä¼#ƒÙ^‘=þ9T¯ŠãgŠm»ÿËX€*ŽÔÓÀÆcpú8ö~{¯x¼y®&=âhµßÌè²sÂŽ\ZÐ–q &Ôþ"G¹[²øÙÀQ‰T`ƒ›/…pJÅj´~&ö´Š`· †ÆB[Ë’VÖûWÆ·HdßÞí›TÍU"ÞÄ–¯äü C0[‚¼CÏdÖU¶4Ó obƒýQ$†ÿâTXî•$š"¼Ýµk4øF¢Ô©¤o³AÿŽýMÒ¨Ã²¢î€X¹@%\Ñ×zEMQÃüï|(&0ï¼/]>7-þÉŒ¶èèö¿Ï‘ýg‹á—Ê¼¨S-©6ü~kvWq¸Z;}DÁ®4ºcxš}ŠÄé,àŠ^ÜÖBz»0Ú%d=zýIÂþ§ÿn™Å‡‚-™ÔjG´uÖdM-•[^üìtÙÖÙ0‘‘­Æý•=bÊ¿A@É#iF:«{’¹»þ„Z¾s·f³q°‚ÀÛhü	ÞÃýøÈm{Òt³çÊAí)”¡<Ze
“8èrƒÄ5Y‰—bDÕûÊIØ–ê¾ãa¬J˜Ä£ˆ%L,ls²þPAÔOOo=ºh\g¯Ênk‹ZKK7ÃœØ„_GÝÒ
«y÷3Qiè7î™÷§xV£o&ªSŸþŒ!UÜzþàINÄ˜†rþ¬Û~5Ð„^Œ¼øôH›&rDvL$H‡™~€Ø¸ÄRU€üÐß€S`ÒîTIB åÂ¯`W#¼ej{ÌóR‚‰->+~ÒƒWñ/à<Ø¿gGY³Þ‚ß—JNB’~q¡Ú÷EQq³E.¨~OõQøåCÂÄÀýX¤Â;x§}Ã*é¬±µèx¢£…‡—kØ9´>U 'Þ^_œ¬üh®£ÀM"ï‡“~ëNQÈÙØ¢_gZøéK•1ßmƒrö¡-ó„1ÑÜ:dú*G*àõ¾¡6»7ÊÅâ¦`þ´þƒ"™ò@öšò¥Šb‰‰=íµÑˆXü×õöŒ¨ hÒü h‡ÙÆä9®oÈëÈÄií,",x0‚”YaïFýf,c/}L¼" 
{&Œ³ÿ”öÇ•¶ >FCnS +ÌMÓmeCà–ažqw4ÊTn¢¯íœ“‰ô(cË*td¦“6XÓ'§“äÌ3ÃË^‚]À
‰sDõè[Òþã#‘˜z|6øOxQ—j qzŒ‹7ÿŸ˜QÝáÆ»]B¹µì«iÁ£á´-%"|$·sÔ8)0®íÓœp-3ÒÂ$DF¾%1Œ“'`X:#>oBÍÖ69â˜àÉÓó ÷J6. orÃòµá)¶¿àJjéI9`‚4ÒÈK_/¡™Iâáö	¾ B+X•M/žÝiò¦Q SÚhÐ¸çØr&Ê.LQ#Ã5˜Ÿ`¢W5Ï–mRO19Qmü©®Î[{h’­1o4Cû7 y‡—«&€(ñé»zM¦	ír’EÐDþÓÐ5? r©2<žAÔÏ äf®×Œt„zÞ­êgê$„éò†Ð¯÷r’º8	X5Gjs,ÄÂÚË¹ÞR†³Ú¯*›$ùgv~U7Í=ÔÓC<1*ŽRç”í²¼Ÿ{ï1UJ?4-|\ò®ÆOEn®@aAùÈA=—–IœÑçôu[Š/9×®0<´ck"ëÚúv$.èŒ!yiAU{‚»bq^ï“$·â£m¦« xR&–}+H$_—JÕMZ¬Žª6µé‘+unºš‚Ùc´@W­nÙ÷­Ýä¨51í<èùŒýòƒsNfUtÕL¶Y¤^àáx/»c\&/3þoñœßQ¤Z\€Ÿõ_Š_#ZDÈÛ°’Ýz_~]µÖ±Ð€Ó4YÑBþÝËô°•Xšøzr—™°cqUˆ¼±0¡Jyù&èÒ„ÏãWk¬éC“ÁlR $/\ÿÒç{D«I‹Ø ÝúB_¥u¼Zî—^¸û. y4äàUüêÝ/†ÖqÁ2Q¸48;Â¸×ûçÖ0¯ö}ñfªž6ôÑ4ŠósT!pu¢‘&.”š˜•e	/Z2­C ì^E$4%o}KmbªÕRÚn‹–‘žx~s¼Š Ã5ÈêcC4/ÈßØ&ßqpiõð•>¹Sìzf1:‘’pbl€à×……ûµov2:T—}hû¿•:Óe…VÆ
‘>Ò/•‹?©z
ã%8(áå'ˆÐcùŠ‘Ì¢
ÌR¹­J5EÖÐ[²çb¼¬¡n >Qa£Å4‰yCÆz-eN88q&è IûÕû3&}+û._4xj§/ï6Ã£¥ÂÀ‚”Á|*€B	WSíc¸º û‚îSFˆœµžõÖ‚ý ´$Gq¯«¬Py)»•LrÿTÃªež½S·>Ë,„†½çoÖmz¸cÎ{›mÿK…ânðŠ"§ËÂÔXõÅùËò
ˆ’bÀFé.èóçŽô]OwÁ!Y0.Ì0³#5÷ºúC*D%\"l‚h4vB›Té8.­¨_<x`\)¤ü çÚ’q¹`üš²Âç¼Å*«qã9yÐãõBPÁÜ"¶P¸ÍÒ¸è]¦{ÞQ£îÚ«QCô£¹H^9`Oó;¦IÝ5BÈ«ÐI?bÒHîpÎ<û\ŒqíÕ›ž4ñâ¦ãS6f{¬'¶Ö9nÈx ´Îr
Uõ?½‘UAy9¶*UF.I#e¬­ÃX.{!`)í·´šÞ‘Nú¬©{îØÍ\¤<S8&¯ÀÑ;ÉueÎ†q$’°`LWÔ*Ãí¹n>è
Ü ë‰7@çI2	ÈQŒž—Áo ÖÑkBû÷FƒEàlÛ<ÞAn/ž›ÓªO–1X¼ÒQ	ßÞÇyùwÞ#Ç„ÿa‹DJ.ÔxsœÃÑÿ$Õj°Ù%FBGeÌÓ±We¸†É!V÷ÞÎ±¾^ó=©RÃì‚?p§y«fŸÒ=#}Âûuûqn.ð3Õ6§âàÉ™“šT¬XäŠ—¼ÈJ\ˆ9 ±’BÜŸVÏ‡jHYÀ1nª¤œÿÌ¨þi¿!Uh0ïˆ¥cÆÔŽ¦©c×¦ÚAp­õâWÛƒ–ƒî\øöhUl;c%þnÔìÕ8‡i½b.mÊ#)ß|ÇiÈSE›Í¦7&©êásìÂÔx&mñÔð—ôt¶<÷ÞÑLòe F¬Çœz2¹óëÏ8ÆOâÚ/%Bþ1æ»`(a$J:v, zi;°Ñ4P¡ƒ¨Èê¾.´É;Ža4¨ù6ªî™ ±‹<ä_ª&I>ÂÓ Ïé4/¦†”ú‹~VËºdW5Ê—	Ø°„þ$S*~&hÛV ÎˆäýêŽfA@¶kL«Hj=¯-”†K×Jn¡êªm‹q&¼%XÀ¥´ñ
«‘NS^/X3-Ú€´6W%pfa¯µ<@Í
¶ù¹®,ZùrÔt®z~WB·üú5®Ø„OGEVµpÀ&ÃÕÄ(½Ù@·^¸²3áøÀr„#-ÐëÓ`Ù R•
’¿“‰cªò
Sõ7ô]äÝü3³+`›sïnW9é_)‚ÀLZœ]òwJÁzúÒ¬–yêXœþôÕÄW†âÌV&­¸}Í÷hÐÅ"â"ð&¯#m¯IV§|±MÉy¨‘*?Í´ÂUVD…Ðæð¦²	ƒ8vÝü‘*Ç%Ë"ÀöyôŸÐÖ¨žýyõCÌ<Ô£a×ØØkòìÄ¤Y0ÿû·€ÊÅ`L,~q@ ¥|/hÙ€³U=ì ,*eËx±˜O~J fÎ…”h•e}”žûlèÞ™õrQþ7“Jã}ú4ØÙšƒ4ÃtÈ>Ãû’·¯õß½Kh¯ïiÇ lf€eç±ðdzÇØFF]QtØs~­þ)w]Ìë\T.Âlª¥#£›ÙJZƒï*¿€é•êÇQ£î6Ì»WEûÖ	jSãÇâ³ÕÃÁ¤qlìôÕ`êÊPcIëÃ/J.ŒA/À‰?JnÖ/¡Ô˜hN+ŠŸ£{yá¿P­ÏMè–Èùó3²˜ãàÑdOwÂŽb
ÀÅG/·²’Mg’Yí‘Îµ© ÕÇšmìþY°`»J5â]8„}@€Kóžðy-ˆòi.]Ž³q‰0Æ?}±¥ëÖ÷†LŸ/Úð°-í}³\C#êtÎõy¸Ÿqxç fÀ<8`72,qsD	Ž‰ïºí¸´¡	†{áæÎÌvt"RÄB=˜ãmÈ>ÛF<¼úÉÃ†ƒj’v·%OaCfÀaºø,ÞãH=Èà³Vr5ŸikºiZÊ˜ ø$T”ž~rÎs2‰pûß~ågÜ@}ˆˆ‘b&,ÀûÄ‡S=%áeöU2+¬œN úàn`t€:ä;ÍÛR”¦b~¶.½P›ó. ˆSÐ%"ËÇuy?*€Óý8^v¾wÁoU¥ÂØ"hm2eÄ¡+˜þv:áèýÁus~ê'˜Êää‚:­aÁ·¸¢CétØH†ÿŒ¡óA*v«½M†]ð.ÖÅÆ]_ÔŠ_˜¾V’XÃ±!›ZÚ#•A;èù;ýÂchƒL	I¸UµŠ!ç$Í§`ˆkþN\VYÂbcÕ²òNMº([ÎËŸÈ£¸f
aõ®¶NÆÂ™%"û¨.W¦Km“;¥EyÂ”æÁ¯"ªrádÃ×Ð
•-N‚(C¬P²A¨§ »=â÷g¨{"_!Í.Áôôû,QM“Za`Ï­!¯§
ŽœØÓ80Ì¯¸>M@ÈÀaÇ©L@]6	.Es&«d9´ûÛ®Rù¬z½7Éå7ûªŒmòè”óM³q)´þ½"a"÷ZåUÇŒN*©zAƒ+?sv&) D¤Jf)•–r3 ’¨dsM†Wj‰èóÀ÷<U@¡JÂþô2«‘,X¼%<°u9•°ø´øB7ó“Ô6pÂå‚âZºwÇ¢Êsë›µðÛé==å^ºVŽ¿}xåÓVÙ\Å6ŽW’IfàÅúg»ôZ·§y7Úˆbö˜GPn±Â†Ó