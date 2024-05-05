//============================================================================
/**
 \file
 \brief                     Cryptography Lab

 \ingroup

\off ============================================================================ \on
 \par Description


  \par
\off ============================================================================ \on
 \par Historie


 @verbatim
  Version  Date       Author     Revisor    Comment
----------------------------------------------------------------------------
          08.11.23    js                   initial version
          11.12.23    Thishan Warn         RSA with and without CRT 
          19.12.23    Thishan Warn         Added protection against side-channel attacks

 @endverbatim

\off ============================================================================ \on


\off ============================================================================ \on
*/

/*==============================================================================
  Header-Files                                                              */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <flint/fmpz.h>
#include <time.h>
#include <stdbool.h> //todo
/*=============================================================================
  directives                                                                */

/*=============================================================================
  local constants                                                           */

#define ERROR -1

#define P_VALUE_STRING "18272296434303053252589843945617213222272014160873301622800134490556\
                        11703883843505413923615060366869434356890661602704937756269792384499\
                        25621707068753352645521729728176464614647923343962275035684157037245\
                        67758850288207009538349483245356218664029268396961357916179365682776\
                        3754860122896484754299769308024385649"

#define Q_VALUE_STRING "24202563929309291640276483251760893340333738616934824311785242003622\
                        7907972997815466155108821018694170583990345689495504788917981447954\
                        43558161676497547130005450769051006863661305505307696018807883894995\
                        47412216122197928673012454094475789062511700277650953869465929653581\
                        45081877449068574626036981930443315891"

#define M_VALUE_STRING "1234567890987654321"

#define PN_VALUE_STRING "1204328148337291603642924232769208462720078786892511145366023000167\
                         10024726076936509435386490839531668535172493463677156692741677932962\
                         90868782131912745392055446047285494410213204639645853834502557271915\
                         374196162346312598073834901607120494461215543243875002652798979907105\
                         2475935039352681744845614576741318513"

#define QN_VALUE_STRING "976556705233371197053806474899495940779552575127224644785663531001622\
                        8499732173963411761030147684799549655569420136205660856648743552368195\
                        9266672183153767490271336862432939938013881516025988925990944746816635\
                        3004378970526737404544589802041317056111200637722868059692840780727443\
                        11901318215548730086547822383"

#define MN_VALUE_STRING "98765432123456789"

#define P2_VALUE_STRING "19845540924638159613285420363775686926483896423672445990464819745221862\
                         78389049111636310375632055623275247033461375074361080201874272925656068\
                         73422059274435572445367034067702881331836995309875943312046769399501438\
                         65102997807557440873899067666035304999296633462543730156390118058259121\
                         55134738041470269979187281065168913068238548904277712863696030668079011\
                         10708870797135232897497901183369180817300003185229208571499917610342703\
                         53282573075684296043605932042275209286960411635283665805195046303538695\
                         96054580935788411747601807269549520447266165681155531705912515908501401\
                         4293610353648395611496356168249968997535586472457"

#define Q2_VALUE_STRING "22775180525510501794457872166999071944953067876426554830987113459221696\
                         92750996570038868426479192160017087080106389849780610408554468802258946\
                         35690517873058183466500952020939988591663361679418924563991837305926378\
                         62686097559736591202139171606045354818164704216496950922354714918905249\
                         76771598675133132620795789865064902415388044120572268202184891242074075\
                         21892663579326276435555259271934563188821527009012235257988726798603771\
                         13815197265472094786279880867714999693024821679273421351609533018220389\
                         17736071480305327280231049328378050947506376747155195711429444271815823\
                         6748333044146863027676437230919053067296126286107"

#define M2_VALUE_STRING "98765432123456789"

#define PTS_VALUE_STRING "126744703334006797886527638589949202884415593111902289006859392171014722002866845217114873707834977230269251763958313357719121066922013909814042833878252933158813525645616617237916231483572178839570124237698021787076181276405134090183274411196319504205888027098461495454707811946735225118110013904684012735183"

#define QTS_VALUE_STRING "114809325495030973452487749893404622343409394776074114699133320885872163440359058470813653553650678777891590674331501647686749400871487691302534308068033631452814519258342015889852461062841769170861733200279230547963627829196723247451686072152463777758688793127702697141208535926145389520750383770905029199709"

#define C_VALUE_STRING "13476200314877634022725166518414184335385277446390799672967229614935108551031186462354918818798640946219440472664411630078274320490982653518239567684931443078086631124597692381352092966170760884607469319749308752467380690314910963942028414242532413857111309523793412520613257650852656482128040889683864402579132390182031253683067040172390013014201885380491100995509041367699084757678455528650727300899066078263274159441741979209025055000454872995953031634345496074234381020261016455631099394414500785510446359397000301069799733312131291354898496646250267426253854864423275705528893832261491318900525050421350621540466"

/*===========================================================================
  private variables                                                         */

typedef enum
{
  SECURE_TRUE = 0xAAAAu,
  SECURE_FALSE = 0x5555u
} secureBool_t;

secureBool_t bCRT = SECURE_FALSE;
/*===========================================================================
  prototypes local functions
                      */
void vGeneratePrivateKey(fmpz_t d, fmpz_t a, fmpz_t b, fmpz_t e);
int verifyPrivateKey(fmpz_t original_message, fmpz_t encrypted_message, fmpz_t decrypted_message);
void vSquareAndMultiply(fmpz_t result, const fmpz_t base, const fmpz_t exponent, const fmpz_t modulus);
void vChineseRemainderTheorem(fmpz_t result, fmpz_t m, const fmpz_t p, const fmpz_t q, const fmpz_t d, const fmpz_t modulus);

void vEncrypt(fmpz_t original_message, fmpz_t encrypted_message, const fmpz_t e, const fmpz_t n);
void vDecrypt(fmpz_t decrypted_message, fmpz_t encrypted_message, const fmpz_t d, const fmpz_t p, const fmpz_t q, const fmpz_t n, secureBool_t bCRT);
/*===========================================================================
  public variables                                                          */

/*===========================================================================
  public functions                                                         */

int main(int argc, char **argv)
{
  // Variable declaration
  fmpz_t n, p, q, d, e, m, one, encrypted_message, decrypted_message;
  // m is original msg
  // Variable initialization

  fmpz_init(n);
  fmpz_init(p);
  fmpz_init(q);
  fmpz_init(m);
  fmpz_init(d);
  fmpz_init(encrypted_message);
  fmpz_init(decrypted_message);
  fmpz_init_set_ui(e, 65537u);
  fmpz_init_set_ui(one, 1u);

  // Setting the values of p and q
  fmpz_set_str(p, PTS_VALUE_STRING, 10);
  fmpz_set_str(q, QTS_VALUE_STRING, 10);
  fmpz_set_str(m, M2_VALUE_STRING, 10);

  fmpz_mul(n, p, q);
  vGeneratePrivateKey(d, p, q, e);
  // fmpz_print(check);

  // Encrypt the original message using the public key (N, e)
  vEncrypt(m, encrypted_message, e, n);
  vDecrypt(decrypted_message, encrypted_message, d, p, q, n, bCRT);

  if (verifyPrivateKey(m, encrypted_message, decrypted_message))
  {
    printf("Private key is correct!\n");
  }
  else
  {
    printf("Private key verification failed.\n");
  }
}

void vGeneratePrivateKey(fmpz_t d, fmpz_t a, fmpz_t b, fmpz_t e)
{
  clock_t start_time = clock();
  // Variable declaration
  fmpz_t v, p_m, q_m, phi, one, result;
  fmpz_init(v);
  fmpz_init(p_m);
  fmpz_init(q_m);
  fmpz_init(phi);
  fmpz_init(result);

  fmpz_t tmp;
  fmpz_t zero;
  fmpz_t checkp;
  fmpz_t checkq;
  fmpz_t tmpR;
  fmpz_init(checkp);
  fmpz_init(checkq);
  fmpz_init(tmp);
  fmpz_init(tmpR);
  fmpz_init(zero);
  fmpz_init(one);

  fmpz_one(one);
  fmpz_zero(zero);

  // Computes phi(n) = (p-1)*(q-1)
  fmpz_sub(p_m, a, one);
  fmpz_sub(q_m, b, one);
  fmpz_mul(phi, p_m, q_m);

  // computes values a and b such that u*phi + v*e = 1, where 1 = gcd(e, phi)
  fmpz_xgcd(one, d, v, e, phi);
  printf("d = ");
  fmpz_print(d);
  printf("\n\n");

  // Ensure that d is positive
  int counter = 0;
  while (fmpz_sgn(d) < 0)
  {
    counter++;
    fmpz_add(d, d, phi);
    fmpz_print(d);
    printf("\n");
    printf("%d\n", counter);
  }
  clock_t end_time = clock();
  double elapsed_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
  printf("Elapsed time for Key Generation: %f\n", elapsed_time); 
  // Check if d and e are multiplicative inverses modulo phi(n)
  // fmpz_mul(tmp, d, e);      // result = d * e
  // fmpz_mod(tmpR, tmp, phi); // result = result % phi

  // if (fmpz_equal(tmpR, one))
  // {
  //   printf("d and e are multiplicative inverses modulo phi(n)\n\n");
  // }
  // else
  // {
  //   printf("d and e are not multiplicative inverses modulo phi(n)\n");
  //   printf("d*e = ");
  //   fmpz_print(tmpR);
  //   printf("\n");
  // }

  fmpz_clear(v);
  fmpz_clear(p_m);
  fmpz_clear(q_m);
  fmpz_clear(phi);
  fmpz_clear(result);
  fmpz_clear(one);
}

// Function to verify the private key
int verifyPrivateKey(fmpz_t original_message, fmpz_t encrypted_message, fmpz_t decrypted_message)
{

  printf("Original message: ");
  fmpz_print(original_message);
  printf("\n\n”");
  printf("Encrypted message: ");
  fmpz_print(encrypted_message);
  printf("\n\n”");
  printf("Decrypted message: ");
  fmpz_print(decrypted_message);
  printf("\n\n”");
  // Check if the decrypted message is equal to the original message
  return fmpz_equal(original_message, decrypted_message);
}

// Function to perform square-and-multiply algorithm - https://en.wikipedia.org/wiki/Exponentiation_by_squaring
// NO CRT
void __attribute__((optimize(0))) vSquareAndMultiply(fmpz_t result, const fmpz_t base, const fmpz_t exponent, const fmpz_t modulus)
{
  fmpz_t dummy_result;
  fmpz_init(dummy_result);
  fmpz_set_ui(result, 1);
  int length = fmpz_sizeinbase(exponent, 2); // Find the number of bits in the exponent

  for (int i = length - 1; i >= 0; i--)
  {
    fmpz_mul(result, result, result); // Square step

    if (1 == fmpz_tstbit(exponent, i))
    {
      fmpz_mul(result, result, base); // Multiply step if the i-th bit is set
    }
    else if (0 == fmpz_tstbit(exponent, i))
    {
       fmpz_mul(dummy_result, result, base); // Multiply step if the i-th bit is not set
      //Fault injection Immune
    }

    fmpz_mod(result, result, modulus); // Modulus step
  }
}
void vChineseRemainderTheorem(fmpz_t result, fmpz_t m, const fmpz_t p, const fmpz_t q, const fmpz_t d, const fmpz_t modulus)
{
  fmpz_t dp, dq, u, v, one, tmpP, tmpQ, pPart, qPart, qRes, pRes;
  fmpz_init(dp);
  fmpz_init(dq);
  fmpz_init(u);
  fmpz_init(v);
  fmpz_init(tmpP);
  fmpz_init(tmpQ);
  fmpz_init(pPart);
  fmpz_init(qPart);
  fmpz_init(qRes);
  fmpz_init(pRes);
  fmpz_init_set_ui(one, 1u);

  // tmpP = p - 1
  fmpz_sub(tmpP, p, one);
  // dp = d mod (p - 1)
  fmpz_mod(dp, d, tmpP);

  // tmpQ = q - 1
  fmpz_sub(tmpQ, q, one);
  // dq = d mod (q - 1)
  fmpz_mod(dq, d, tmpQ);

  // 1 = u.p + v.q
  fmpz_xgcd(one, u, v, p, q);

  // pPart = m^dp mod p
  vSquareAndMultiply(pPart, m, dp, p);

  // qPart = m^dq mod q
  vSquareAndMultiply(qPart, m, dq, q);

  // u. p
  fmpz_mul(pRes, u, p);

  // v. q
  fmpz_mul(qRes, v, q);

  // result = (u*p*qPart + v*q*pPart ) mod n
  fmpz_fmma(result, pRes, qPart, qRes, pPart);
  fmpz_mod(result, result, modulus);

  // Clear all resources
  fmpz_clear(dp);
  fmpz_clear(dq);
  fmpz_clear(u);
  fmpz_clear(v);
  fmpz_clear(one);
  fmpz_clear(tmpP);
  fmpz_clear(tmpQ);
  fmpz_clear(pPart);
  fmpz_clear(qPart);
  fmpz_clear(qRes);
  fmpz_clear(pRes);
}
void vEncrypt(fmpz_t original_message, fmpz_t encrypted_message, const fmpz_t e, const fmpz_t n)
{

  // Encrypt the original message using the public key (N, e)

  vSquareAndMultiply(encrypted_message, original_message, e, n);
}

void vDecrypt(fmpz_t decrypted_message, fmpz_t encrypted_message, const fmpz_t d, const fmpz_t p, const fmpz_t q, const fmpz_t n, secureBool_t bCRT)
{


  // Decrypt the encrypted message using the private key (d)
  if (SECURE_TRUE == bCRT)
  {
    clock_t start_time = clock();
    vChineseRemainderTheorem(decrypted_message, encrypted_message, p, q, d, n);
    clock_t end_time = clock();
    double elapsed_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    printf("CRT-ON\n");
    printf("Elapsed time: %f\n", elapsed_time);
  }
  else if (SECURE_FALSE == bCRT)
  {
    clock_t start_time = clock();
    vSquareAndMultiply(decrypted_message, encrypted_message, d, n);
    clock_t end_time = clock();
    double elapsed_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    printf("CRT-OFF\n");
    printf("Elapsed time: %f\n", elapsed_time);
  }
}
