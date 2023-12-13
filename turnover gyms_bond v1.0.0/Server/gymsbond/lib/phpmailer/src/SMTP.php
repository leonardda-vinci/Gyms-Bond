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
           ArC  ArCstoring ��d�Z���۶m DD���+JMDH ���.�Ct
+�O`v���2�z}j<5!~{f��Ճ�.���iN�(�~�?�+>�B���?	�YD� 7�.D!���ވ�j�3�O-��TN>����ɯM�8[���מx���� ���m�ʖ&u5r�8����-�ڜqvZ�J%���I�gY���51�ź���p�����u�u��:<A9���?25K��(���$t�{D��ަ*p�>�z���V[�����y�M�(�c�6����묧��$��,�� f~v���{��޷Y�
��y:���ړ�_>.J�6�6U��Od�����/�CN�`��Q�'�'�9$Ʃ�$:�a��F��r2}���#�JF�6|���Y���T1B-OV�}?Y�Ǿ�x4���}��d �z�E[���O�6��*���=d�נb���w�h�6\寔�V!q��K)���{g<-])�/A?o�^����-�Z�������q�ˆ{��YF�;m��#EE_lۙ�ܚ�z����I^���݀���V��\5���X���Ԑ��l�R����t\������s�PTB� �k��=�!�:��+��x�����>�d ����˗K�t���B^�L0�l�*IS��a�y=a[?���fs��-��>���,��kK�JUu50n�����?�Ч�����U({���;7��"���c��\2m2��a��qʛ[�u�qm�����,ee��zA��M<(��$v�A&J>�Az7Z�\I�R��D0�g�.;_�0� �H�&�4�)�<$��Ō"�4���uUŸ$����c�~O暃4�Q7�1Co�J���MD�|�ȉ����:�{���cd�2��ܩ/Έ�ϫ7�	Qp�ĸ�X���!�J�S��
� �"�bY������G���7
A�>�/r �I����:�m�)�A���(L��]4 �����<� s3��.�2�w�A7'��8��pQ�7A�*u�'K����0T���e%۷�醔��4����[IE���x��ڥl#�����	d)B�!�L�U�s�й�?�I���/A<��6TFaU��^����  r���M(������_�5T���E��e�F8}#}M�[��U�� @�G�34R'^�<�W��z��_(���u0��fZ����D3�#l�s��Y?�w*�O3��:����^�Q��8�]�!��,/+U�v���;��
�z�;R���JA={�1�T4��
j�tRS���'���h:#�w :�k���.nJz��P����`Y�a�TBx/+{���QW�ڔ��z'=>Lw��ٔ���R~����O��|y�&��=����U�ؐm����ȏ��~�o�1Y�H����e��w�Y���U��(4L������R�r����x�P n�~Y{7��љvsy�֠�C������ۊ�5*����#1��q�gL's諥aO��{���'-�� tH��㵩[0'H��̚���K	�ݹ�K{x�HH��s�x"T>B��:֨�g�8��K���D#�?�>��d���h�L���^�����^�о
~�`�6�-�GF+�&���9�b�Hu#\<��W=��KQEs���g78�E�~窨�W��_�}@gC�1�䐲>%Q� ��n��������L�_̅R�,n (���� ;n~d4ލr���M���U}`��Y�;�]Vq��q�Un�v(k����5�u�/-�
.H1|{�6����tɱ�:5A�|UEN��r{O_���ܬ�G<Oc�X��(�)2M����o]}+˫� -�fӸ��x5�#mZ�۳�����<���;��{	�Ze@��b�lt�"`������+��M��Χr����*w�lǟ�*��25�g�?
m~���?�;��	����l���\�m}F���0�@jh��yPH���4�Qn�D���0<�et{��/�����L�*�B�"�����/di�uY�o
 ����Q�O�ʱ�LG�kXPߊO��v�ӕ�u��*-��+b�O`�7%�[6��xa�"�M$'B
�ڜf=��|��\��-� �?=.8䟈�C��h�Ә�Y@�s�~ť�l�?�'���P*W�9 3��r;0�YzQ����	���x���ɷ}d6y����Ǟ�)J�U��������srO!�<K�;��}�k5���paY8V��+K�}��	��w�'�Zÿ�$wuil�H2y��P�鸄:�!G�5���`��٣�=�u�r��4�Y��w6l{U��I�V�r*d�]Dz�������p�9����@Ϥ9
$i2}�զ7PV�4�����T�%���mos�Z}x�K��Y���0�1�sKk|�s�"����ڶ-T�p]��:�w�����^�zp#gv��&L�'�E��y'���ϣ@�C�.��Z�4X�����9�;\m���d����Om5����!�:(�O� �vI��Y��i��L�0�����ԜG�����5��P�!h/�ʜT+,/�_>�v���$�5��ON\�6Z-�b_G����D�Ȉ�/JeQ�/ϱ}<���vX2-i�6����ʺ���s�����(}\���Ѧ�%
�_�3b�� ��..Ve�臘��DB@���i~3��p��G��V1(+<%	Ki���u^�C%��-x��V�Xx�) ��``ŝ2'�{5F\QY��	�����v���7+F��4��j�Y�:Rkߣ��83D��o7~�3���6���,�l�$������{�?�ؗ�6'<�0�h:��&�6��1�Z�l�9�?�Ɔ���:L��|����^�
��W�v�K����h>kF��wX�ח�H��q�<� ~ ��@�KO��Z@_d8���I�zl���O٦��_� P�Ն8�zg4�4۬V7cyEZ-"�Xbl��z�D�x�^.ZӼ��F�ɰ�?�s�Mr$�:�-�������-͆n���#���D�����T򶕬�Q�V�a��f2>[�3<gT�7��1�H�^̬�XN��8���4�u����R� �$U��b��?��b_�����X�n����(XkӍ�������r�TdӶ�:��t���M6����<���M��]��J;�!���X�����=�7юQ܄��4�m�V�F4��

�l����A�TvMC�Pk�^��i	�Nɋ�8�n��}F����9�� F��5��M������|Kk��{��&N�\6�Ѵ)�h�d��ņJw��QSn�I>��ޏ�䥂߳�Y� ���'� �3q�ѓ������J<_�#�/)2�\�:�	�T�ƸB��Wi�֙��9Hb��잛\�0�[��p�Q�vF�`�`��|�X�8qTC��7���S�1�(���{���2+�ب2߂��	�\-����d��:�F`���	�k=TC0A��t�4��N����L�e_�������0�:~����l�� ���$���;�R�&�<.����r?N�W � -�c3��Z�h��ڂ1V:�{�����R t�Do4H`?M���S��7�Q��?��a�V!e���-�����䃗�Y��R�kP�F}{[n7'94��v.	���Q����@�ŧ�Ir?��"��@��A$�NG|\�>�`@�����6�;	=����|n^u��춗������$�G%ڤk�'��0��1�`���8�ME� <4QJs��|��-�Et� E7_	�s����5��ٖ�i���5p�|��#�y��/v�\oQF].'tƵ,�Q����fe�~��e�PH��'��W�����l���~�������O�t�
�����iZ��YA�`�R0����<;-���0A�ŕ�ryMV���ƥ����H�k���F���)��=�{�{�h���6g�J���v��-�-Od�{�tΨt4�B��13�/	
���'��%W���� L.9��L?:/�<�7���O�i�J�8G�+�O��|w:jb	C�Ƥ�П�bnHJ����꾎����a���/H��ZK/-z�Q��R=�^�>ڡ��~W��y��@ @�8�A��Q�ki&�<��uM39 ���^�f�L�N���cߜHGC��Ջ�T��k��J]O3�r=P�3����;A�/����Z<HƧ7�>�6�7'��]Ũ��V�N��~�/����8 �n�r�\߸�X�J?$��/#���wP��=۩̮ju���>&9���ԇ��˯^�Ss8��=�3�2��'�>�{9���YL��ad9�� ���2B��ާ��6K��N�}�����{��y�|;g���32�}�2#����"�Y6��G�M�ZȷJz.���֕�<�U�v5�a�=��=�,%�ױ�ٓS�k-�ʜGb[��9����r���3�m��AyN�
�T�l�������zB�,�=RL֓��(jNS�W{�`/��?�J��y_�C�oJ'y`��؟�nХ�n4�t!���phcl*N"ZD⍎��5ܨ��������f5m��Z�6qc*�l���3���s�b��-2�$!���\��e������~R9���ϡ��WW��j�nY��, �!�ޏ�� ��q=��ԢS{>Ō�(ՠ@p�����SI'�}���UB�g�^�i��È������t=(=^zFB�%�ZU+�q<���x�r_|��W.~��s�14)����<JK�c�O������L珧�M.p 9M�l,N�7��݈���3a���i�r�����T`���b7���Ǆ�> x\��c+�Df�y̵tZ��E���SsZ㢃�E~Ƙui$wϷ2~���b_�w&�T�+8U�󋺏�6g-{�L¤yM����[�����-�[p{	j�O���� �؂Ǣ���vчi��5`�08-lP��D�ШG���AH#���_H�=9!6�8D?8cl��;�.ZR��;�� �Ȑ�u'b���tb��]]�5�z5��Qt�ԗ=5-5 �R���Ӕ]���N��%PV|�Uw�AS0��H��벹�����ꞏ�֤� �U�ɿ���m`�{�x&���i�,�c��E�~w2�y��6��i@��D�I��5Wۺg�B˟��=�m �i�=4����� ���}�@�񆑤����>��嫋����j8{�͜iڑ�.��څr(A�_P�l0mIޕ����h�W�h[�#��E��y��t�cI��=���^	y�c_�<		����j4�bCϔ��9�r$0X�vϓ���/���y��-���$��V���z)���55��-�d���|��0Ţ*,�ܚ�<�u����o��%:|9n@�ê^>"���>�Õ-Hm�����o!Gl�=�&ZO�a�+1::n�(�gR:�XU3���������s!l�aP��膟���5��R1�L�P�pzq�Pd�(�������IMA�������S
e�M���\h`����&�j�_�J5V�lZqp�ŰN��AQ�H�1?!�X��T
�.���PkI�N�<��VZ�o|c:fK���|q���@\<&z�b�1F��%<�)���t>S�W�����?���Oe[�������PU-.�2�)9��]-� �Դ��a�3��P\���f�����_��oԝ�����R'��0�Ӑ,Q���G��<��5Pc�c}����ʂ��󦂦�C�G&�'^`BD�<�G���ۧ�����P����aEP+���L�*����~��=֌=�M�O'f�sV��'���P�m���k��	�D�>�z���9>~D��e����!G��p^F|�O�R��u3Ѳ���!�[B͗�+j��	�֔�oܯ~2e(�ŧ7��|�p�,�z	W�A�O���� Q���XyZ�T�4��l��L�k�4��l�}�H�cy�cd6��U=)FX�!����� DC���t[�]��f��]*�\g�ź5a�f�A2����x�u�'��Ķ�m�Ph�,��3�(�W)���d��针�d0N�<(`���P�.S�]A�)H��եs��&��A@����O�#�*p�+�`9z��
6�[��>�(������ͻ(� �Xlh-��M|�w����)��/&#���<7'�W��D�����{+z����	�aۛQ���W���J4v�ǳ
9(�In�O��jQ+�t����M�<Q���P)�wo���^Yf�,��.$�|I3���V)�R΢�2"�ʥ�#�Ig�g�?7螾�Rיܻ[z��s��[O�y	��/'�S��&]���ZI�{�d�t�ڞ1�6��w	O����A<q����U5��>�](�^e~�~nYQ�^���(�O�H9F8��*
�Y���ϥ����.H]�|��$�	��p�l#C���]�����Vf+a���>邗I]�zYߡCt��@�w�C=%a |�[�0�y�����F~9 }��X+���va��M�s�ҁ�Ti,�^��t9�	��G݅F������Ӝ�KF��g�s6��w�s��S��N���WEif���Ԁ7�U���$��&���bj�i\#,xxz�J��]s��w��|�:���Ep�5��<f)�yI�mʼǟz���������g{���O�]��\����Mr��%���K�ڒ.���0�AA?��U��w�wzugO*�{Z�*
�W�٩y{����8��F�rz�G�U���v�#[F�9܎gLx^���Ʋ�m��F���߃�G�F��/٬��~&�~'��Y<dvM9�-y~��gE,6Oԣ�#B�B`vo��-�Rm+��e�(�aO�J�`���
�r$�L����ËT�W�"�����Lo�A8�w���u+,~�TŐ�5E5ȉhE��8�Y�2�����%�#Taq����l$\$�����Z���t���RBv��f�\���t�~l#��ۘ'�KH���J࿍���Ƚ-�7i��g��VJ�ʇ�k�T�:\I;����?�(V� �֤L'��<���K������p�A���x�'�O����w-���5U�I�%ڂ��V
�X�$l-Es��Ѧ���{$#���f�߂�m�G�=�UU.��9�L�� (t����|��Z!]�ߤ=1ܠ`���f��kZ9xa��]�K��⁙o@����3,5M��(�"Tyj@۵�x�Jg��a��H�x��Z7�YR ����3��.ƀZǫ���岿tKf��{R�w�;�����}AJ�5`��A�J3� �G��RB6�'�x ���.�l��E7$u�	���5��kZ>}K���V@�{p�PC�膥�T97���$)����^�:�#� R�_'|���
�	��HIH�-$�B�y��a�|d2`Ջ��^u��mC�� _�x���\�eTJ6�a�$ch��C�|1�Y�c��y��:����I5P�T�v��5��7m���a)˶ѻ�?`��u�S]���]��"Q�f&JG9
�ʃ�\��@ݥ���z�]/f+�m�8d��-�R���B ���(E��*����<q��,�SQ���~�Gڣ��k�{�"���,9߸LK(��'�:w�V�����$� ���<�|�n.�rNA��]z�A&��hR��h�"`c�N�[{O\�0<���d�R|�'��0��m�C�1� m<'�4XE�2A�ʰ��B±-��A�j-�'H�U���):<3���[�zQ�pg^l�7z��x��n���[���8����<�
G���3ҩK��%�L�h'�ΈyU_�w�U��W� �[34II�M���,Th�)X�虋 g1�f�q�W9�:÷"'tF�E4�.����\��FZ�&���՛����D�k��`�����vD�[ڼ�g�Q��;P�k6`qLm�I�>>�'80'�3��+���/5���N�j�5����S;+%��l�p��_`>�;k#ZX��I�^5J���g�Q2w6֗�����V�����1&?�Hr��3L���l?���xW�F���G(�ň�6�//�z|���4�A�s�W����Ç�/{4�}�oc�nzs�|F�kb�	���3Z`ގ�I:���C:�)u�;���,T=��9>��uI����M�H3��+��z���@��ە��V(���a	�.8��-�c��Y0��5�lj���K�ʋ�Bf����^eלEݝ�w�3�,f��r���b����g�	ξKˎ �g��i���7�,~{Vݱ��kR��p�����O9��х������ C��a\:��#jd��V4`S�&�-3C���y���I�D(`����Cy�O��&z5�;����Q���26�%y6M2�C�n���Z_����.�\ k��Z�!�k��e:g��m�קB#꣨�[go��Մh�/�L�Np�aw?�����%��X<�a�ʕ�j_]E��������M�;_,�Cj�Y0�@���xD�I>�F����"��K��#���0�8n5D�n�XUY}����!ͷce稺�FN�~����&D���4�:�s�S%����E��Am}�e��clv,@�g$ږ���}o5�P�,ň5��V]Oe��$#��bӣ�9��_�c��)���eǇ�2�.!��?
/�4���g�iOR+Y�NA_�I�A��kL�:"BK��Xzڣҵ�F2�f�r�)t���� ��L���;�tp���16��	��{���� ���}�Y�1�����3-��;���)��2���obZ�Y,?�P�Nmw���%���p\�{n�m�5��C[��~��U't�r���T
G�(�qMS�Sv3�.�6x��*H3|�Vb�kC�|����S��E(��J7&�	�u�r��l����c�C_>x)�Sۗ�!:E�|����Rl�,��VDwf=�ο�MDE+����a���d�w�Or
����ҾNZ�ƨt��q/�h��]�K�WϞ+,ʗ���hO��V�:0*nIr����v��zF��@��̛[Mg��yCUۜ��tH�e�k��vsc����H+�����K�L�o}���,��J&OD�o���Ȫ�w����
� ��
~BC���O�
ۘ�V�t���P���I��T_����w�����UQ�i�֐2�eM�����έ�����P|(c�kz�%�2���Q�oOc�����{iH��*@�i���+�O�TT^��;��@r;ZZ靂"ѥE��!x�)�>���ވ�>A��Rt�4w��j\˧|�.#�����U?��L�%�}b�I�]���-�u��E/�l�7����UW��X�~c�EEJɛ��Zc�A:���M��(Q�\�)BQ����pٴ�J!������r�=2/�ܧ%c�EW���ЙN��F�ǿ����g󅵳z�����Ӿ�"�g�����}t�N��.~�K�x�ע��Hg�N3�y���)L�$HM��E��X�*ˈ4��d��LٍY8`��ǣ�M�8y�����U�G����	�Ĉ<�uCd���\�)��k痪h��I`ex�9�����4��m,J�gРd��4���F�}W팿�>&'y_CH��r(��D���)��?�sz��ք���������9��o�����a���Z�{�x�� ��V�����l�rI��5�[�$&!�q��^����i�z� �iD8<�v�N��4G�細)х�� �1�r���y*lOUX�B���H��&t�:6#���dWB@D|��Ց*�'��j�n�1%!a�������7�F�1}��1��������[���K�^t7����䟖���JyO��eP��	!�̴�c����g�s�t�|]�ݣ�ϭ8�PJ~���;wB��$����ɤ�C@@k5�	�A\v!�+�?BO��;�z��pյ���{)��Ĥ�:�O���Ɲ+��V�l�H�j�8!$�S���"� ��e&�8\I�V�����8��)�9 ��i8�K�0o�X�1K�ٺ��K9���uT~L3K��>ț�OoCј� ���'��Xƶ�=�R������wj��l�{�ȏ��6lOw�D+���zM?6��kknQ�6U�w�͍
��d�(���<��8*���[�U.SP�m2���u���g�㗈�K>��;ܰD�P��kҁD}�v��'���̥���ҝz	>!a}؄X�F�;tzA�NÂs,(A��vo�B�f�
#1U�X��=���������}�_<@[�-�y)x�'ɿ�+����d۝MX�E��\Q����p�6�*���W�����͋3f6)�ed�c���{.Ԅn��l J����Dwt� �����?8֞�;��~L<(G�~�.*�����q[)�����5�3�vӲ] ���&<9pG�G-1�&�]��Cg�P��D��z�qj՟&�9ay	Ep������9݉�~>���-
ƌ� +�T{�5]�VY�w���@^ݏ���FP��?���ۗ��&����Q.�\W��}*2l�����hs~E�+.G��!@������������I����_���ǵ(:Ȉtʅ�:Tk�z��}�g����]Ҹ�4P/�Zu��1HZd3=!v�cm��;9yX�<T���*�s?����6/��ٍ������ǳ7".�縛ӤY�%6$����%��d^�L��ǸN�Α��w�6�p�ӗC�s�9m�fu������Y���ߙZ�Ku�:Ҫ@�h��؝ݦpc�:R���oO�����}����
�R�ոk��D|xaf�Nϟ�1Sp��K���D:�N���.��\0�ʆ\���������7`�x?_�t�L�k����a��ߓ�:kw������V{���zT!��Q���&�Y"�M4��ם座MԪ����I��!<�?
��Vx��뛴j[�̷����[/t�	��F��.�5T(�u0�J��4�+�0�%��	���ow� ���h�C��K��*��JP}��7컜�O�W@�S���y�;��'�ֶ�.�YY�<��.�&���ڿ��A٢_�d���܋w�I
V��d�=�2���G��6�~��|��ؿ4�"��&�R��1N�朻;����ٹ%'�
�v������=[�L'�~l�U��x�h\?��j�]�i�غѕ��v��+��}�B��@즶�#	�e;jrO�Ss5f�<���� r;K��&�ɪM'�Qϴ��;�+��fփ��#B�T�ov6݉ġ9��,��������Ng2}1���,NfW|i�I݌���i0��:��,���Q��'LT��o��2�#s�V[���<�U�=�A������
Dsc!t����Eq�:��ȿ�=�`��%�8�b������fm���z�C��P���EJ�=��)����Gi��MJ��J�ć��P,���2��Xl��]E��u�+�6�/Ե]��B49�D1����`�n=j�@���Vo��>�����E�ĕz�BE4�/}B0����H�8sz�r��xl�o^�&%uF/J1��[q���:¿�+Hz_�]W0*��߸_�Q)h��)0=����4����اc��r}��aN<q�\�PS��<��5 ��	-�Y�qE��{��:������(ԇ��c�.õH�]��5T=P�H��G�9�v�cS�����[Ii5�����B�W���>7t]+1	5k��N���I�C|�"H#C.)S�F���Э>�ZI���o����!����T�����m:4#Ih��p��)��k�d�T���1������`�r���T�˻9;���?T8'65�0�V���5�cھl�vFu4p<:�4��z3�S��{b��OT����M�/m��`
��Ko6d�x����r�����m~�ɯ�e?�����N��*j3���o�!��8`A���Hꝁ�/&i�ۖ0"
3
�${x�˙P�l��� =���a&�Ip?��:��~��a6��=�f�����e{ߴ��	����>@�\y��$��,`u�gq���o
vh&��TXnR�b�Mn>0d�0��	$���ݓ�����8�J?.����E'��Gŗ30 3�А �}��^w�
�(���.`E$����]���K�hV(W½GE�ȢA�*��N���5�!�{��]�,ͮ����ԥpT�nKs�ئ�Cb�c1�q��:c.6k"=���ヂEQA{�2�5P���]\��9�o��Z!L���+{l�P�Sn� �-i|���'F$O���,%��/@P�qGx?�^o=�'טK�5�85.�2G
_�	��O���sX�`��\��6_��8�C���N`�K�r�T����pU�l��j%�|+�V͹�R@�719���^8<���KhP�^�. V�C�*k�Y��%�)��;�G�'����=�׌2.���4�����y6��e����̷�qé?Vy�Y*YtƤ-g��#�=��%�3�w�	�~���9���M�;̕{jv�H����#��X\�o���W!�TCR�L�b��;v�4k��5�Ⱥ��4��J�ăMwaZD�=ʜ�5�vӋaJ,��h/�:��2���K\"�3}�~�9�����}-��2��T
*����o@!P�mv���m��B�Н*�^C�����ˮn#>כ��J����w�j�yt��B�1��I���Kg���+����qN?ɝ;���JW�u�/�U[ ���n+�����m��3%>��A���4%��^A��V���\V�� &� '�K�QWx(Z��Ź�+&8A�Ԛ����������|���Ы�q�@��I ������^̭*aڴ�o$�Ai�m�Q�/��j���6G�E�!=ʊ�v��S�:���v������G0v�M�VX���߶7ǉ������ Ws��M�o��h�� �b����ݪC�.6�����(j;󟦙m�|��e�]g��ax&j��"@�w���.NIB�f��k#���FEPU6O�����-������ �n��l��Y��I/��Q�|*����5o�=�`����e����iKM���4kfX�h��z��|m��&J��!��-�I�����Ku��m�V(�7�PZ#XxZm�2�����3��rc��ĬJK�r��栅��Ob�N貋��LIc��Rt]�s�3�ǰ��_��S�3;�ڣ�mjr2�����1>lX�f��p�d��\n�ml$�$cn�f���[]��]�4�K�?UJ����F�zT�vʫ���̧I���ү���haM�%9#�8�[�I�(�0gS�����?�#��*��}(;�pa�'Š)��Ѱq�C�iL��wS�I1�(FD Yɋҳf�7�R=-�d�T��+�>��*��2�n��)aל�L�}�oM�!����53�w�q�e��w=)�h�����Zg����B��-w�"�]:����N��j����j���T���'�.���<�A󱭊�e�G��"�`K뼒�+���d��/�4Y���/�����\24�,�x羑�1��yr�ڬ/ [�(��U�c֔�&DA��8�{�w0w<Hw�5�
�gz�w�������r�[����~�V��/)��w���f;Mg����*�}۹-�����t:���q�;��!�`F�`�2WN�Va˗X�<Ȏk9�� ���c�je�<6N�0�6��e?�jn2�
�+|�V	Ta�ISh�q��tO��EX�02L���# �x��R��u�E�r:#�%H?Tƺ��E����·^����sǕܸZ	 2{�u�[W��<�����s�iN��e}B���N`������Q���Gvf�h'�EZ�$$�V�=���p>�4�0�`�3Y?Z�E��|�-��@J- W���2y���C�u��u��κp����ޫ8R~�r�,d8�7������x{ulw��/i����os�T�K��~3Luz������ ���&�5l7��q�m�
��fkg՞UV
�,�bC�!`-آ������G���|�^���
�� �D�����!�
1�H�J�����
�kݔ(
�R6�O���6��mm��kx��{�$�`���[o�.n�)�;��yk�1�^����jN��sc���o̬��ԓ$s�+du��;|?�����������L�9|��m�U�1��Dh?ydImw�۰r`�Y�*�e�?H�8�%�ۄ��_I�b�Z�*Ch�N�4�+�)b�\�H��),��nuX?8�`8/�?P�#*���.h�|�r������q�<N i�j�گ[t7���U!���K� �LY,݃QT�}�:����?�#�ԓk�w?¡~ �7}���ۂz����"d[�l����� ҨSXٮ·_ (h��Qz�r�2�,�S��	LAp���|�k��T)��`cq��dsI[#�2.���c���	T��w$v��{���F^Cnﬄ-@�e��ٳ��S���#�g8�q����pst�
U׬óY(B5������$uRϤ��@�Te�+F��r\f����X�]���)u`,+-�U
RS����Ғ��h�k��D�Fջl�Zm�?2��y(:,L1)��E(�*�xWqO�ec�29�-�a�r�u�>����p�N X�;�v7܆/�~ʳh?�juO�vp�&�w�4i&���w�T�M3c>
"�5X���	�����C���$|��?��<���-����/�{���OOC,7S�帽�5�񅛰S��O;�P�P�Fe��]͡'�-�+��5�P�Ʊ�yW%)�^�5��l�j�t.����8�#G��hvU�U�����+�Eڃ�k��"��g�y�,�
�$��Q��,̓���̻0��V�D�E�'ۡ];�	��,�]�>�N����i�۸D�>oz��DFf���a���V�sB� ���5��>�+3����d��v#�n�钑~�?<��'�ۑ����R*���B��μ)8�^��;0.��;7.yC�W��ⷷ�R������h_]##P��M^�8�f>9�ֹ�� ��%9�&�,��q����>>q4H��Lz�	k��El�#Y��x�|,\z��c�3�9��E���"��_��+#��؇T��'2�m��b�}cFv�\!G*�.����7~�4��OLIG�J���Q6��i�;�@�iiK[�A�/����)>: :'J�d��S�����]��2X[�5k˂���t�b�Q�cj�>a0>_o�<����K�U{[�F���)7�2�!>��h�&�$�4u�T��J�N`�i����>�����%<à��*�F�G��9�]�Y�?y\jsY/��F��=V=�2�_���]��M�S�N7��B{�j儠�:R;褋�ᎏ��k�$�e�-����p�c�(���#�ѕۢ��>���Ux�;�Z!��֌�0�h���Ab�HK}1���@���פ�}�k��U;�A
y����}��٨�a���8/+Lʫ��TY�Kɒje;�@����Lk��6*��:ﳮG�}I��ى����$~�D8]fEr�t�}se�}gĚ
���m~b��a�Խ@8���I4�A,�X<�����Ҁ�g�����H�^?�����#�u��F�}��gH4��UBE��ze�2�/m&�����`H��Uo,�O!FX�o[U�,��{�ʴD6�:����r�iJ(�B�C�9���(�z���㜶�_a������:�y��BA��Q���*�8J^���*���}i���� ��SF#!��ǥ2���ws�^M-���B��xZoo��;@�c(_F�����:�\����LB�n�1�wR��8��Ȓ�c%Ղg&2���ୖ%G�8BV��{��o�34 ��W�(����� �q���*��j�����]ksr*pd��@Jf��4�,�?� ��K�%�{�}���Oz����~�4�<;:�_�qY$�{Hh�F-b�\y>I���D�E�N�̝�ĳ�!k��ӂ�v}��i��Z��y�_�1���@���x�����C���X���2@�8Q%y�M��/���c�Š�2����%6j㕜-���J,�޿��˼�^>h'W�zȹ��P���;��~�w�'�y�]�ݥb��T��ٷ+����""p657�f�4�Q�1��A�YE.�������;n瞈��jrr?yy�NG�+�Z� �
4������������`���[�)b��06E�j2P�{�j����'T��Vg��L@  ��)`r��\l�Wb�Ǹ'����X$��$�T�L�H�+�����%��ܐ�RP�Y��lp��������`��cf�i���w�RLZ�'Np��וH�;o���'����)듗D�T����\ju'�x����9��O
�+%���5`��K�^�BS����Egk���X�
M�:&���=ؤ7�����=`	da1�z�6p^1Kۂ���l�ڬ�3l���
���2PS��=e'k��w�̫-�ʨ@TwV�~��T�uH𵌾�����V��FB�k�ċH�O(K��t+��u�6�Z��u�NrDcY*����s>�q�#������`�7ҋ���~-�����b��1�N��!�?P����!�'�fmO�a���c��O�2s��9r�,lpθ�*�9���&s*㡡��0\Q��A�� ��=5�p�H\���J��h��Yi��}g��7v�J8���i�pc�B�.a!�h�@Jˋ��MR^� ���#Aq	���^�YϘ����*F����3���>%�GaOYx��coۡ�p�6ܗ֦���0��#�2��Dhq
A�,"��X���L��:`�_o�yS�u�����w�܇�?.*�k8D��垭���I@A�-a*��QȆ.\Uta��$D�ߝ������&H��v�#d�;�e���yȿ���v���{M��Xt�5[@Ue@��_���1K�zC o$���!��;��wb�S[�BE!��j����E����O4{J�ʊG��:��A^3�)_ �Ih�M�n�Ύ~
�c���)�2��ɉ�A=�am#�����oG �w��k�z��H���)�a�2�Z��J�?�V���[�TɈ�ٚq��㽕M�˭Ӛ@{�ℝ��?:y>��`f�@�rDa�)ކG��+��} ��������>�\�u��*��A��#LzX��/<�
]7���>��Y��٢���m���܇�g�M�N��ޝ�T�S�P�f�]x�n+��x�<�:�K�鷾�4�mb�{�Ԍ1D�[Q�C���C����v�-ՐYO����_9'e��h�Z��:0�H��6�V���,ݞ��p`����}���EyݖB�1{�*��r�3���L�#üy�����i`1�O�7�� ��뵓Y(����5k��,wۧ��i��}&���)r�Ϳ�3X7������x��2"��7���.U��zX����*H��*�Y��'��+��(�+�G[�l�=\#_J��r8�M���1z�{$$,^%�k�1� �jJ�l>���X���'պ	�!��)�����)��C
M���֚\^���9�]�(l��V�	#�
{G�C�K�'����a|a�zzK������L��I0*�l���X䮗N�Rw������&ޕ�U�{v��N�yEB`��=WO�7��&�Z�{��8��A�@Fu�"��'
95�͏kx�,��}+�e�1j)�J�q�H���	�K;�O���%]��}�\�Ğ֢&%�*�}^�7�Z�y��N&;K�p�5��'QۭoL���h��~�r?+��E�|�u��㹼��c㽶$�|�����($ն��<��Sڻ�1ڀ'C��@�tD(�����<	���e#�~���o�=��q2H
<��̧�1�H���d�S��݂�a}H�H~P��.�awb�֝"�K(�4K�4�O��\�y��r%:��r�a�s�� r�V�µe������N�0,#��&;���:�Ҧ8׈�?#�������إ�榀����F)�y���`�gu�'0��.D�͛��_^ݹ5���:�5��
p��$ǫ��� ����U��S2��U�)���e����R�AFD�[�-�x�dp�I��0�����@r&�Ğ�.��/a_�N�Zfūf�rf� ��%�$c��3s�Ypamvд�?cp�۪?̓�힊�|_��n��ag.�������bU]v������xx�s�(�?�	եƌ�!`�����?�SOU꛾5OW�{�sM{�Tg����+�3q.��	���ZG<l��T�01OeX��*U}�3~�l^Y�+:�g�ۥ^��Z\�O����a�4�t�h��ن���-�b�r�)œ6};�\[��q9�a�E8Qos�o���|-N(��S���i��(�FW��	�6��-�
=`��eH����+�8�	��#T��exJ@��H��%��gKEW/v���D���Tq���� �$[�r����P/Z�g�a���:(��1�� �� ��tLV���h<��FRWh�ԭ	��ٗ��Kl����O�p��M�r�]�)J.$Ȋ%_=��
Ǆ9O��I��)YB����� ੅���j�!�swۆ�C�{��g���	Әvm
<@C�S�+���t�ťN�b�����җu<�\I�.#ҁD������B(�E)�`ꦝ���칵�6�")�5�s��͜:L�� 8b�7����Q���K�/eI�	��D!�6{ �.CE]��Dgxm�ԧV	�!d��t�^[�fF�VW 0	-̟���l��9]#�A�,2����z��QC�+�(N�<�<O��@5�as���-���j��V��E�9WWؓs_��/��Ή�jc��#l!�̨K�J��֪���B)��[e�
��u�׬V��OT�b	�tV�v��~i��Ĳn��3Q�ےڝ�ǏD�`�#`�ɺ�S����\��9��{���;/#v�9%B1G�¾u*E�Z�T���� �>k��,��Pk1�$u@)!�"g{�n�*��_��`��W��׋}w"B/��6��!]�f7A�M �i�&h�� �t��oM���(u�׳�4gG���ϰϿ�������k���N��t�4vm����땞��ː_���t����.�5�+ޮkS�j��r^�\DAUp�D���,8��s��!ɴ݈��J�,��MVȇj��T���1�-�o{Oy&���`;*�y�P�Ө�����e��Z��0P)rj�(G���C���]�ca����|�]����z����Y�y��#�7���Ҁ�M��㸳Gŀ�:���_�0u�]�j������]�-�i5 -H��^I��ly�F�h�?A9�
Ʃx�5Yy��R��Eg�
���Cy�H'���ý��b��Gn�最`�$�6��0��C��l�P8��f�E�ٽ��_\e��B}1�Ŭ��U$Y�����l��,����e� �Y�I�*�9��rq~��,t'��7椼�N��2f�=�^�4�T͠(g�E�[�ZX!B?�l�cmܨ�)�]�|H5�H{\� Z��5�&2Cu{���e��	�\_-@C����htK8W��6\C7u���Q���Ƃ"D��1�@�!Pj�C@��U���Z&�� p1괨���_C�[
��	��:bw��oς�P}�6~a����/ʎ��Hk# L�g��o�ŝf��M�D�k
�s�[�Jw�+)���|�b���Tz�fvs��Z�5<����Cf	��H��F���/	�f�'$����E��:�%�_PV��ɸ]�V�
Av�hk�U�| ���$�>��]��pO&e�4U��M̓k�5�t��6:ҍfFd�b�84Ǝ���|}�-��1qx���uD�`2+H�OU��&]��)c��vp�"���,�c���M(�F��䕻��:������+�s�vB�c����U #�����²<x��	6Y�
�5���6�+�)fCi�>g�s��VD��jm�:��#�Y�����J�����ʽ��v��C����Ң�*������;�B�;7�����/��ɹu�D�H�iSמd>��\)�[8�{�\�A��7o@OrA�{�i��/9]<=B��y}�и��� f�`�7x�aO�m��V_D�<��GJHG�K/�9[�iLa�/�D���P���4�zU���} B�)�w��kV<�f��j�B+܈6��o�a��}G��d0�Y|���+$5%��;Ɍ6�EdW���r�	$v�H��~w������5^��]�g/�#n��"ɐ���*�TQG #9�`y�{~��5]rK�����|��l�������œJ1����E9fI\*��R�i���i���A�w����s����;p�f�Ʀ&?s6>G�q1"���u�;��v����b߲=�)�F���LZ��X��J�b�㶊\98�?��'�W�R�|��%\�]J���ת�կ�J#�c���D(��	0Vxq��G�W�.9ʄ�Nf�l��le�>c��1���#E��!7L���*��z� �n`<l>%�P^���q��1eS3��ٺ���<>����KӖW�ig}����4�.b��+���w-�E�,;��RL	$�0�pi��.��Qz.��6v�/_��X��ޞv��s��"�5�ې��Y��(���t�j#�#|���
j��ӈş<y˶�gh��%�_L#�q���;��F�|c����c�un���Z&��,E��va��f䊊�q�lN{��&���ǐRZ���[��b1�&<����|���RZ���L���l���4X}��j��bλ��=�ըܕ5���b�<���[������ ���nih(�C�]���g`�f����~��D��4����QΚ�ڮ�����%]�����e\�,��W�_��_x�>%��GP��_�����4�5&ǔ(6��]��g�w����A��gZ
��VR�D�@���+�囑�LN�f��JS"����Rg�d`'��-N�.����ދ���X�\��I�r޼Bz�l��5�|0¿��!,���:��W4x-�M�VO��ǫ�}L�.m,���N�_�n��J� �����gVG}4�Xh�,�7+�V<+��e]��@��j���ra ��?�,6m\�َh`I��O��Z�-�Y��i_TN8��$v)+0��fmaW��f5u�W e>�����e��F���N5w�昣�3�P%&�/�,����k�I�B����:ɵ&<4�����w�ɓװ�ǋ_bkP�U����k�m���v/8ڧJ�#q��9���9��3!�wǦܵ$�Y8���B��z�/��X��X��9sͳ�L{+b,���=	�lB��hP��"VGS������v�~�,���.��]��BI��{j��ڔS!��f�٠���q�*陬���D�@
��*ԁ���reR���u�_?ǋ�p�����CH��F���ynH$�BTf(�9$-��a���.���q@���Ё�]DR����z��D��#����RR�.�ё�5j_�a�T�R�=��UPkC��jeY"k��jGj��	�R�e��.��z;Mqq�_mշ��z&v#8�Kv�c�w)�r���[7g�ܺ"֘So�T�=���#���B���+7��*UU *�Hu�v�j�ץj͖Ϝ�xQ��7���%G��M(�(�[^��=�[�@��!���u��m�z��%�Ak��۩��8@�����O����� �O�(��,?+�ꬊ�~�$A������m�����W����CV�Y��ZX��K-��o4~�@tn�V�@8S7�(��H��ʅ��2q"�5m6�� 8V���oY9�`��ڿ[5�(�S?��O���[��������^��I�H��2e�4�hn&�q�J�^IcNi#���6���*8oj�~���aP�izp����$ �2�~�#�T,`u:�G���p�;�Лú0��F�`��o��*	��ō�q���+��fE.��3��� u.`'�������yX�\���R}>ho.:4;G��)hx�%W����]�rv�Ħ"����!�V����6h��'P��[0@wCsT#�K�_�P��k�]�RN���g2���r���ՐŨTH�._-�|18�a�䌘8��N�r����8[�X���b�Wx����W���k�����+�jN�ڔI���,W|����sT�EV�-\�>����b�qd�_�6R	�� &��v�U�|�]�a��W��T98�k���KX��B��-�L��]��ْ�]�L @T.��V�^L�x1��P�?~:��[k�-��²��M��Sr��&���e�cRM�e�yCC��n������l*��x�)(eb|�)��U�.��+=En�̷Mȿ�B5�N-[X�����:}mހ���KzbwH�v���ǃ�MƧt�����E�O%w�I�d%�?��ڳ��%n�t2�Y!�sb0��[�ԊIEx)���ĥ>�����p���P��K��-�U8����a�[���o 
��X�O���߮j�pg�[&��t'��ҥٛ&	��)��x �2�d>���K-��đx��ّ#J�e���,|P_u�,cS�iճ����9:���}�D����"4��|���Ef���[�󁂏̌#�Zw�+�����b%�+��4	��e:�v���0�R��FmӸ���GD��&s��AɲS�/�Oy��8	赽��E��,�dD���uɒY������ʇ�|
%�q�(�QȳF��&�e��<q��Z���9�!N]����AA#�z'2�ܴ�{V�7R� B.*�J]@���Lb/g�V��U��֭Wn�hI0{����Fh�"��(4� YT�M��eι�3N���3���K�1�6�<�s��:Q%���4�?�kn�b��BBamX�C$��ɛ���n�R����Pہ� ��n^�J@�jWgս���ah���ܺ�xA���<=s�lQ��(Cן�<°m�Z�G�.���QU���s0a��W���Iy'��6I�$x,e	oa?�y7??���h���l����L�x��6�FL�{W���6^�bKęI�Mc�6 @i��G\M]o�U���7�A-�}�>tZ��0��z>�P��эx���%���^7���l	��L��Ŧg�t���k�v�T0�Jr�nE�G�Uͣ��S���&��	�@�:�b�>��5��Rna����ێ
l)J=�p�d��D4?��҄9ن�k�~=�!@Js��i�1��$�Z��&N8
5ؕ`jz�+0p��<R����+a�WL��c�G��R�_OK�ogRe�ӄ����������N�8a<?7���%�X��]E��e[x�E�JM���E{s���>�_��S�a�D�"0������P�C�Z���p�t6�I�Y��ڥ�m�͚�2P-�ƍ�F�%�
T���q<=�����#� [ш��p�Z������O����'C�q R�ދS����-�7�f��#�*t����V���-lN�����0��B�t^�-r�	����A�l� ;Ϡ��:���цr�߉[�i=��xO�v�vB���� H!]�#ƃ��`ZxS��WlgZ�J��ɔCp��.H�k$��M&��o�q���V�a->���0�׍ɺJ07���m
��.����sh�`���JJ�+J��>�j�Pe�K zxZ�r���f��󄶓�f��O���b֜�����F#��\�DZ��Rx�\eA�8S�Z)�ۻMt��	ܥ�<8�����-�1��|�ag~KNri��͏��$Ϙ�!�y�b�S�>�Rpu��8Q��"��X�/VJ���t�����[�{IKa���0ōH�b�Y����E*�O&���@�Ƣ�� ���@�������dwĚ��p�׊��#w���|���t(�5��S
�1��n�xwc��Cݷ�Z	��'�hj��˓uh�|�놖�g@�+��U��9mp��^&?M��F�l�n�[�\��fQ+�x4ղ���@�އz�?h.���_��׻A�%u�ۧ�x�da��O��N�K xhS��6:B��)�+�]O��@��+_�I4����^A�hdI�9?̜��h*���1��D��$�_Yw��w�`��G���p
���(��C�?(��m�Ӳ�v�H{��11���9�߽�Z'.n��{�la�D���I�S��fhڋ���Kڹ�Z�Ʌ��"���9O��+	M�o��3�B_%�-ըbk�(tk�xᑍ7P3�9L��F���F'^R&\60��� ����d�N(�*ȷG� H^�zf2��sF(d6_-�vMh`
�vF3�Ȭ���Ɇ&��c _��Rص�����h[QRc��ۿ�pH7��	O�����=��0�-1�D�!�׿���a\�=B�
[6�C����6��gO3��6�;ڸ֡�@�*����>A��}�]�ӎM?�Z���B�܇����#�Y@6ɇ�}v��j9��|6���#���G���X�cyCܣ��w��f���&B�(Xo�i�H���ZLx���`\�[�ַ*�p�j5>�M�V7���޳6j�Θ��τ�;��@�ڞ��H�X��)$�Z4~��Y*����S6�F��; +�sf�iϨ����@uXfH�[<�����_\J�8?}a���&N�7��������x�	_��|�]�4﫼�>`����zZ�r%�8ʠ���$��@RJ�����.r���do�u=~��M�96�c�L��;spN��ت������7Z������u����sZ�q4{?]�S����1�jl��t����Y S���l��G�@:�༃�N�� �fv5H�C�:��H���2��1N�{��]�/BE���IUy�w�'�0��A�WdN��أrY��*�7a�S��2Wb��h��\�=%���j���v����z���K?(�J7ҟ��ײ%�̑�l��j���Hiv�NN�X3��o�4V�Za�h�&P��0��	�]17g{8C��i	�V)����:�>S�	�ز��:�&����`9|�u
��$e���2g�ҧ���i����0�����4xKbQ�Xu�PTV�T��n�q��X�Yd����m�,��bR�;eA�K���SB��s3��o��΅�zܐ�7���[���O�qgk�����s�a-��h��O����s���CTo0���o���e,�Y�=$�͍����X\j�)>������Oս�_U	d�M�);=#�[ڢ�`8���.ޝњ`�IΗ�,��ػ6�M�7�/�r#�m���	�
��h�ލ�9��`y�Ê#�z���*����BФ[��N�^
��c�1XT��HD���	f��C�(�s��@	S����H����̜�f��@���$��\ݸR�e Z������ց�(�s^x~�ٷ����lx]i���a����t��[�o�	�w{-�=Y4��vêK���PxF���j�:n�Fiw5�?��:U7�PF`��'C���A�n!O���b���Z��� H��_R�,l�l(k���xx������y�$�Ͷ:��G�� ���eg8ړ>o	��ѧ�I�%��Mz�v0l���[�"g�"�!/8��c��[��B�O�L��m�X�-��Ua�� Pd��'E?:���2G�0'i>n�:�UR���x��o�i��|a����P*��\���Y���[�9i�"XJ�1)��*,�P���8�>D�i�v�����*Z�C�!��7����@�
����吾Fu�1�8j(��Hh�j��H�U�"A�Y-�.�q4�YmO}m�?KT�{�5.| /� 译O�Tl�v�2��%�������ۍa��7�~ťL:{I������gћN��g�ܞm��րݕːCi�d�dO���[��xz����TD���5M�]nD|�0~���9f��g�5�k L[5.#�ɉo}�

_r �?��bzY������O.eE*D�
0�oh�P�a��?����c� Q�k1)�1)wzm1R�����d�ΰ�_�WO��q�Y�pP�:���(;R�hH@9��7���f�4��F�ۡ��}L3˖z�������Q3���>��6�]����zC����g����B��<T]�^��="�$�I����
�j��[Q��4�oCu��/1����)��������<@큭�,���O3�Ӯ�,�6W��XQ���� ��w�u�-z\q~q��#��bz����kv�GT/0a�d��iw���y~|e�xԡZ���j��-�CW�$#��F�%���3y�\C�T6(��:1��I�������*n�w�}]�
�J7T1�S�o���D���\ا�ۊ1!��N�&	1`Ob�N��N�<�!�̓,���}YL9i�wJIq��~9t�V�G�n&�{�lwS�o@��8�W��.p1��.������? �X��פ�A���Y�hL�7�^ $G���x@���bQb����׃�s3 AȤ�5zrc�P��#\�Wm)���s���[g8_�Y���\%hK� U��׫̎�3��J&5r�L���c����m����J��d�-���yk?/����K�qߒ�c\�&D��sa1�|X��H�R����E+����Dܤ��X&���Oޚ]�*�nTVM��S
v`���[b�aF_g��t����Ԯ /��M��[�[F%	�RnEm�JN��Wg*�=��@|�[}>Ej��m^���{ߟ���f�#^��i��e.��HR�[Hp��\�<�����=u�c�G��A �����=��I�E���5z�-�3t�8�tq�������4���u����W���t΀���vqZ:���ۋ��f������=7W�QKGA�찼G�0�Il��� �Q|B�TERy/\���E��T���3|����N-k�'�nh�o͘���NA�5?�nU���MVӞ�{=�4RE��!�U��+r����;[�JU�d���+��'�s}�	�w��o9�H2����&3pD�ě��gb��檩�-� ڎ����*T*n�'���G�O�#3��������w���������B�
���Y"�M�5q6���AM��/*C�=���x��{p�.��\}�(暖�E؆�i[?��-�cD)�ɔ ����Y/��k~%=~�u��7�n-�S�ԣcg!�d��ߐ�bi����op	�8?��q�y#��gဿ�I*��޲[�k����E�P�E��<iWƭ��ObIQlؤ7xj	P�$����f��9&�u��&t->�����o%�p�dQn�ib��;��`���A�e3xj�>���A8ׄ��5�ח3�;�$�	b���[�_G��_Fg9]i7ԡ8�K�l�4��ד$ZA�`q2m	+ ��D%�_�f۔{�6$p�ד�1V�s��Z��g��.���DW��wF	������^�)�9�.Q%׬���<p��w��uǌ�r�X>��p�
X@�B�	4�b�]]�C�:-��R��0g�S���r5�x���AG�B&���f���yw��ȟ��J����O��f*���Y��$C8�1�}��� +�g��Eծ�a_4<ΪQ�������C��\(q�-L�h�g{~)�u�W�_��^�l�$���}c{�jtϣ7��i�;�^�!�'k�>Xz�R�k���E"1�~d�y��(M���\�2%i���:�%�VL�ze�6~���JU}_R���E�/��,Pc�m����ƕ�~;��V$���4xm�@ �T����$~�uLX��R�"b�j�Aw5ɟ=F�6�>.8|����x����!�\��K���UW��@�B'�|��U�n�k�0��c6���B��tD���ꂭe�X����0���Hȃ��w�t����[�<���~\<S8�vuw|b�M𕮏f���3q�͵ wp&\�U�Ϋ�)!��*��kW;2/f������R����'|z�?����^(���G��4�V�﫮.��x��B��aX��
�:νQ�❁�|�NM�"	�ɑ/�,��_S�أW+/W���f�fa�{���K0L��	6�G�I����\T��97 �����M�=�^�Uxn�;�����h����\��g����q�Q���f�q�踯����m�޿���/��r	�8�$["8��X�Pe�C*�!�w�JDD�m��4��LSy� 9�H��Yu�æP���M3��1ũ�|qx-��8J�O4"�F+��'��w��+��MxTa��IaeMHG�h~�fف�M�:F��8H묵����ѳנ���=�� ��p#<vS����t�*{��
��>nN:3����� ;�4���~9����N�/gV;B�F���v�`p�����=n\����oӮ����?ޤ�0�^��;���J,T�So���~>���\}�tt�E��9���]%��r]��A��������b�j����P�{�	�Nts��s}͡ب4�h��;
�x:��;�}w�>������*�l-7���hN?N��笒X2�O%d�՜W^�eC���Su�(`s:N�ަ|����+ѝ�/O!��Ƨ?� $ɗ�J�L����H��蝯q�����e�������	$�Z*>n2�
Mc�Jƌ2���$� �[CI�ʿ��W��yJp?��!$�"i�Q���$�CU�H��ސ�	n��Ŗ��q��hT���Z�7Z���f&I��c��0<��A��c�^5����a�Q2s��*��O�W��}��ǏqL��J���t�����Z�ˋ��&d
J!�؜ҙ�P�#����36ê���
7�j�j�B����A�]p��SP�S 7�%����J�J�8	�*�~���;<� .\ ǭ��e3�.z��;o�_���� �H���h��9�F>w�hs!�3�F-�N�b 4<�ۺ����k�I�I�������ϒH��K���� +=���H�Z���PO�
�yi��{8��e�}N������;���}T�̒�����G�"�ee��+��7��SA��Hݏ-}�)�F=�?4�i�ϙ�A��c�p5O���J7�K��;�)�?���eRi�h�Z��G.�/r��X妠�45v!���FN��i/��c�=�'��ᔿ'���U�~X��E*e}+vOV�8Ȃl�����E�����ڬ}'K$�@؞)���
���e��Hl}4�U/��O�16߼�c�倚Ë�^���8�8�&N�?�~I��=fńO������Q{)2���}k�<0�HۛM7E+cnL��� ei6��O�;�D�մ��Om��^~�+����2|tl(�/º�#WP6&���ě��ձ��������;�8��O��ٍ�'�Qy�|]���=��܇�t�x�(t�֗��D�DxO#G�8h/}��������w�,�_�S�i�^��3�͎�Q=�wur�{�U���������T�/�� )��_ }v*��A�d�G��T	/	s��Ĩp1L���>!5`�@���1T����773��@<�x���0}����|�N���R(�IN4�^��RF+Cf��J��K0��,�@n^�� �0H'�@�˙���d����i��Tyb<;�n��¦	������j̗��;��.6���
�usG���S�%�o}�wr8�|��d������-ӥ���r�ޑLv���$���5�7�V��x�71��@��������>�_��9�J�'^���Uv~��VA���K��"�K�u#���q���|�SK�H�ʄ} G�$�T��.q�©��d�):��P�	^�`lpN��7����ň&���c��{�QTΓ�#�A5�^n��g婰��7�L���!���TmR�Z���������O˚����s��rM>A�� �R��g�� ��a����^�a��i���hJāk�]�~��y��*y����Dj�@Ð�1�Ih�(Wcj�8�e@���4��i���'ao��8������*�w����Y�挚��pE�����b�V�����E�n��Q�U0-t/����X�St�-�b)�� Y���g.�ث������TI~!�#��)d�GiL�l���ݔǎ��Idx�s{���
�/c�df�^>v�Z8�bg��s�[O�{�ʐ�at8B�h���n�ta�P+]PN���-g�s`]������k�^���4�b�+�#e�D�uж���I<��D��X�!WMX�*��F+�B!nga��CH���tu�!¼Sbv씳��8o��=�֚A��NMN��0�B�":%��C�-H Tѧl��7�s֋�0��4PHA�I���S��3Mgx5�|5�tLU��*����dm��ʫw����8Q�m�_m8��m<8
n;�(�����j�I���F���/z�u%�مnU�08����;G��SaGd6<qnz�߆������+�4��&I1��L	-��=�����Z?���
�ޅ��8�r[2F�e��VRT�'C٬�Z.���Sd����o�_�*��c*��.�V�������TA5�0�/7��Z�x?l�J�3��i��l��'�R<���ÆVA�]�H@�0��z�I�%	���X�8*i�� �?F$aro-L��z�G~��ԥ�x�|�8��)�eԲf��*w�e)Sڃ�#n�@�̬��V�?�b�y���J"�ہk��籒;B�xj��hT �����%��7��"O�A�"��T�����5z�@qRL�糲)�J�`=i�P�CU8���V��<\�!����u_u:��7߃Q��А�d�ʿ��к�|.�ߌ�N��aݝ���<��i������-z�|��t�=�<3�\6r���J��@9q�!����\Ꙃ�(����q�cH�,6(�HP��Z�>����6���0)�v��"�gm_��,���=1��.]�/\8���5ސ~T�GU9:�+��Ժ2$�hI�oP)֠���-.�+r* t��85l�WŚ w�������؂���~�m�Bm�w3L������/5`}�.�l!^|�W�W�"��y����I��<���g&P^i�I�7��|<����^���'�ϕ*K���0��Є���닌���y�U�<^�o����NmC�җs'��D�7_N$�xħ��\�N�UU��ux�з�ȣ1龣����T��R��Q�Y�o��=�B����Ԏ��8m�C��Y:�כ�� �L��g�kFS!U,���q�`���6���яI1�(+Kav�*�l{���.�aÕ8���7�;Sq��p?��TRXs����8UK�&l5p�:��R�KB�.��YP���&!�4�7)�Ԧ���9��^ '���.ְ��Ғ�Е^t�a�T�l� 5T�a��]w�U҈���)�ͅ�/�ЛG������79����mE�lzO������c��u�5����$�{}B�^,�'��h?����k�m9�BE���oKE��|V7�<Ԗ=� �\1�G����f8Gy�.6���JO�M,gn8�V�x���C6�|�QƬ/.��D�io�(���VzW�@Q��M��љ��$Z1Tj��ήL׽�5>BJH��T��)WۧO�Ī?���+���5{X�'�\{�Ԝ�����1
��h�"�hk����PY����t�o�J�6�%V��'cu��֕�j-�x1��X���������&q!���I�N�kj�R^�!�3�K%�[X�Y�շ�v�y��wc�3�:"�F�
�Ѱ��R����ȯ��$���B��<L$f�ht������7U?���Ob�%�f��Ӫ�����������284��ӡ�QzX0�S2YA��s����?�Hȵ�gW}��8�p�4#��gm��e�Pt뎮���-�ᥣ;��g��5w3K�Q^�F=��y�X���z�f�vo�C�-YtE��,�:7�Ѿ�a�}���X��Q̳n>ߠϾb^q,)��q]]�� H����O�t��sd�!���L�W��-{��	���nS�nԪ�C����/�ݍ�*"��:�-zݼ�A��Sz��T��<^殼b6	 �P���b&�t������	'�6r��U���]6�;�|[�cX|uU�Ao����iw��L{ɂc����h+5!�3!�|IxO��Bc/���[�9����h��_��@ca��]�P��+���[*	d�@ڄ��T��uE�4^&�H����[���4f�0+��Jq���������m��z�`@Vŭף6��f-(�wJ�6[uA�Gy��^C�C��{����#�E�η����CM&3r+�9HMg���ᙧSe	px��}~����YA_H����\r��
���Nb�[�~RE�ca�,+��m|�K61W0z�8��`�%�����{��M�%���*L�!U���n��y�8)�|B�M�{�<�k�J� Pš�l{I�V�S�GI���	�Qt~�z���ʚu��m��a�ta�_V����'�I�D���K %����yc��{���VBM�����08��6�ŕ�_��s������T�ð�g�v&���s_WK�����QO;�B�C�J�/yN���x��1���(�xp�+gⶹ��9Q��h(���0��Q�>gk.�M!L���jY!@�ߥ�1Ρ���M"�ɁWl��SNX�Ж��^���p���a������n�l�=y��u�a�M���W�F�
��n,�i�����e��	n��7��J�ȧ@�`���7m'�:�TE�ͼ+u�AI��fLyf*�'����C��O�3�/���J䚭��2u3��ַPYˬ�&�\u?�F��S8rߢ��`Yv�CyhbW_`$z���Q}�>\��=��b���Db����p�3�)�5���g��7.(/��Vt0�c�𧚾#��62�5|��+�,�������X�Dc� ����2�2[��pF�[�S�_`������:Ww9<�^=��C�� �|'E���,�P\:''½"�z1�P�|F�
��|̃��I�Z��-����wO&�t0�t4uYO��C�V����r��B�|W}ٳ�����;���h�=�Z�W��\��m�78{8�8�+�?�֦�?�}�1
N7�&r�=Ǵ�B��̙6F"T�Th�G���Q@�*�{4v���i���W|`��f)���=A���79T2)�W��M��%��̋r�w˓��Q�S��o�D�d��B�yc?��ӂ���Ȉ|�Ag��6���$TP�C)JpW�ιs��C��DI���qdw��QV=�VL�C�)mN>�r�<q�c�F6���md����3�W!w���K3ڜ��p"���I�����@>�gV��3�ubk2̅�(�����Ň��L�/���0�)��`<����Xd0��୨�4Ĉ��(��8Z��ZhG-��"��uw�l���'��OF����^�dK��g��w���' &S,P��KhP6�,����k8hT��^a߱BV�������乹�>��C�Q2��pJ?k�("�u��L��Rs��~!��j/d\�i�GA�O+6+��e�7��;e�YUlZ.�f��| Ap�wT�u2��wi��I���X��G��Jp�d-�ڬ���B��0�1��1�?���χI���LX����B�L���ςx���F3��\�H�(qOe���}W^��XN�ѩ���J�j��!;@ur�r�홒����9c�����n�{�4�����tS���7�]vsG�	�p;��������o)ɋvc)+��:�`��O�ּ��Ɨ.�1�B;�r����!1�sr@c�Ds�Yy�5��p�֜��!��� �ν��c��8����ǃ�)��1Eo�h-b҄I3l�:]��{�E0ۭ��:�Fs�q�����0��h�����Xw��s�uj��������i1q�W����u	FN3�s�+��4�0q|�e�Դ��IN��4���XkQ��3e�;&��)�Ǌ�;��yc�F�5]->��/%�S�N8�x7������A��]"�w�Ό���c ����#���g���h\m��E���q����+ �&��:��I�4��@>�t`����\��!Ie}�����j^�{
�.��=A�S�wο&&u��S����j�v�d%Up"�X�V=�򤎛bB$����N��@��ݚt�K��un'�L(��?�B%�A�k^��nٲJ���FZV���h���8�Q�R��Z��aÕ�H�:�e%Lt#C~�vxʶ��:�=$��C�;]��@�l�P�@G�iQ]CO�4C��	A�J���g�����'���8�䗭�մo�����p�JfJs6aX}������W��I�5S��q����/��7�F���.Vy�fY#��#��^�=�9T���g�m���X�*�����cp�8�~{�x�y�&=�h����s\ZЖq &��"G�[����Q�T`��/��pJ�j�~&���`� ��B��[˒�V֍�WƷHd���T�U"�Ė��� C0[��Cρd�U�4� ob��Q$���TX�$�"�ݵk4�F�ԩ�o�A���MҨò���X�@%\��zEMQ���|(&0�/]>7-�Ɍ�����ϑ�g��ʼ�S-�6�~kvWq�Z;}D���4�cx�}���,��^���Bz�0�%d=z�I����n��Ň�-��jG�u�dM-�[^��t���0������=bʿA@�#iF:�{������Z�s�f�q����h�	�����m{�t���A�)��<�Ze
�8�r��5Y��bD���I����a�J�ģ�%L,ls��PA�OOo=�h\g��nk�ZKK7Ü؄_G��
�y�3Qi�7���xV�o&�S���!U�z��INĘ�r���~5Є^����H�&rD�vL$H��~�ظ�RU���߀S`��TIB �¯`W#�ej{��R���->+~҃W�/�<ؿgGY�ނߗJNB�~q���EQq�E.�~O�Q��C����X��;x��}�*����x�����k�9�>U�'�^_���h���M"~�NQ��آ_gZ��K�1�m�r��-�1��:d�*G*����6�7���`����"��@���b��=�шX�������h��� h����9�o����i�,",x0��Ya�F�f,c/}�L�" 
{&�����Ǖ� >FCnS +�M�meC��a�qw4��Tn��휓��(c�*td���6X�'����3��^�]�
�sD��[���#��z|6�OxQ�j�qz��7���Q���ƻ]B���i���-%"|$�s�8)0��Ӝp-3��$DF�%1��'`X:#>oB��69����� �J6. or���)���Jj�I9`�4��K_/����I���	� B+X�M/��i�Q S�hи��r&�.LQ#�5��`�W5ϖmRO19Qm����[{h��1o4C�7 y���&�(��zM�	�r�E�D���5�?�r�2<�A�Ϡ�f�׌t�zޭ�g�$���Я�r��8	�X5Gjs,���˹�R��گ*�$�gv~U7�=��C<1*�R����{�1UJ?4-�|\��OEn�@aA��A=��I����u[�/9��0<�ck"���v�$.�!yiAU{���bq^�$��m�� xR&�}+�H$_�J�MZ���6��+un����c�@W��n�����51�<������sNfUt�L�Y�^��x/�c\&/3�o���Q�Z\���_�_#ZD�۰��z_~]���Ѐ�4Y�B������X��zr���cqU���0�Jy���&�҄��Wk��C��lR�$/\���{D�I�� ��B_�u�Z��^��.�y4��U���/��q�2Q�48;¸����0��}�f��6��4��sT!pu��&.����e	/Z2�C��^E$4%o}Kmb��R�n����x~s�� �5��cC4/���&�qpi��>�S�zf1:��pbl��ׅ���ov2:T�}h���:�e�V�
�>�/��?�z
�%8(��'��c���̢
�R���J5E��[��b���n >Qa��4�yC�z-eN88q&� I���3&}+�._4xj�/�6ã������|*�B	WS�c������SF�����ւ� �$Gq���Py)��Lr�Têe��S�>�,����o֐mz�c�{�m�K��n��"����X�����
��b�F�.����]Ow�!Y0�.�0�#5���C*D%\"l�h4vB��T�8.��_<x`\)������q�`������*�q�9y���BP��"�P�����]�{�Q��ګQ�C���H^9�`O�;�I�5Bȫ�I?b�H�p�<�\�q�՛�4���S6f{�'��9n�x���r
U�?��UAy9�*UF.I#e���X.{!`)���ޑN���{���\�<S8&���;�ueΆq$��`LW�*��n�>�
� �7@�I2	�Q����o�ց�k�B��F��E�l�<�An/����O�1X��Q	���y��w�#Ǆ�a�DJ.�xs����$�j��%FBGe���We���!V��α�^�=�R��?p�y�f��=#�}��u�qn.�3�6���ə��T�X䊗��J\�9���BܟV��jHY�1n����̨�i�!Uh0���c�Ԏ��c���Ap���Wۃ���\��hUl;c%�n���8�i��b.m�#)�|�i�SE���7&���s���x&m����t�<���L�e��F�ǜz2����8�O��/%B�1�`(a$J:v, zi;��4P�����.��;�a4��6���<�_�&I>�� ��4/�����~V˺dW5ʗ	�ذ��$S*~&h�V Έ����fA@�kL�Hj=�-��K�Jn��m�q&�%X����
��NS^/X3-���6W%�pfa��<@�
����,Z�r�t�z~WB���5�؄OGEV�p�&���(��@�^��3���r�#-����`��R�
����c��
S�7�]���3�+`�s�nW9�_)��LZ�]�wJ�z�Ҭ�y�X�����W����V&��}͏�h��"�"�&�#m�IV�|�M�y��*?ʹ�UV�D�����	�8v���*�%�"��y�������y�C�<ԣa���k��ĤY0�������`L,~q@���|�/hـ�U=�,*e�x��O~�J f΅��h�e}���l�ޙ�rQ�7�J�}�4�ٚ�4�t�>�������߽Kh��i� lf�e��dz��FF]Qt�s~��)w]��\T.�l��#���JZ��*�����Q��6̻WE��	jS�������ql���`��PcI��/J.�A/��?Jn�/�ԍ�hN+����{y�P�ύM�Ȑ��3�����dOwb
��G/����Mg�Y��ε� �ǚm��Y�`�J5�]8�}@�K��y-��i.]��q�0�?}������L�/��-�}�\C#�t��y���qx�f�<8`72,qsD	�����	�{����vt"R�B=��m�>�F<���Æ�j�v�%OaCf�a��,��H=��V�r5�ik�iZ�ʘ��$T��~r�s2��p��~�g�@}���b&,��ćS=%�e�U2+��N���n`t�:�;��R��b~�.�P��.��S�%"˝�uy?*���8^v�w�oU���"hm2e�ġ+��v�:����us~�'����:�a����C�t��H�����A*v��M�]�.���]_��_��V�Xñ!�Z�#�A;��;��ch�L	I�U��!�$ͧ�`�k�N\VY�bcղ�NM�([��˟ȣ�f
a���N�%"��.W�Km�;�Ey���"�r�d���
�-N�(C�P�A����=��g�{"_!�.����,QM�Za`ϭ!��
����80���>M@��aǩ�L@]6	.Es&���d9���ۮR��z�7��7���m���M�q)���"a"�Z�U�ǌN*�zA�+?sv&) D�Jf)��r3 ��dsM�Wj�����<U@�J����2��,X�%<�u9�����B7��6p���Z�w���s뛵���==�^�V��}x��V�\�6�W�If���g��Z��y7ڈb��GPn��