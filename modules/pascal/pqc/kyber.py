import logging
import angr

l = logging.getLogger(name='kyber')

class Kyber:
    """
    #define KYBER_Q 3329
    #define QINV 62209  
    """
    KYBER_Q = 3329
    QINV = 62209

    class MontgomeryReduce(angr.SimProcedure):

        """
        int16_t montgomery_reduce(int32_t a) {
            int32_t t;
            int16_t u;

            u = a * QINV;
            t = (int32_t)u * KYBER_Q;
            t = a - t;
            t >>= 16;
            return t;
        }
        """

        def run(self, a):
            """ a: int32_t r0 """
            l.debug("{} called".format(type(self).__name__))

            u = a * Kyber.QINV
            t = u * Kyber.KYBER_Q
            t = a - t
            t >>= 16
            return t

    class Fqmul(angr.SimProcedure):
        """
        static int16_t fqmul(int16_t a, int16_t b) {
            return montgomery_reduce((int32_t)a*b);
        }
        """

        def run(self, a, b):
            """ 
            a: int32_t r0 
            b: int32_t r1 
            """
            l.debug("{} called".format(type(self).__name__))

            u = a*b * Kyber.QINV
            t = u * Kyber.KYBER_Q
            t = a*b - t
            t >>= 16
            return t

    class Csubq(angr.SimProcedure):
        """
        int16_t csubq(int16_t a) {
            a -= KYBER_Q;
            a += (a >> 15) & KYBER_Q;
            return a;
        }
        """

        def run(self, a):
            """ a: int32_t r0 """
            l.debug("{} called".format(type(self).__name__))

            a -= Kyber.KYBER_Q
            a += (a >> 15) & Kyber.KYBER_Q
            return a

    class BarretReduce(angr.SimProcedure):
        """
        int16_t barrett_reduce(int16_t a) {
            int16_t t;
            const int16_t v = ((1U << 26) + KYBER_Q / 2) / KYBER_Q;

            t = (int32_t)v * a >> 26;
            t *= KYBER_Q;
            return a - t;
        }
         """

        def run(self, a):

            l.debug("{} called".format(type(self).__name__))
            v = ((1 << 26) + Kyber.KYBER_Q / 2) / Kyber.KYBER_Q
            t = v * a >> 26
            t *= Kyber.KYBER_Q
            return a - t


    class ArrayInput(angr.SimProcedure):
        """
        int check_equals_arrays(char* r, char* p, int length){
            for(int i = 0; i <= length; i++){
                if(r[i] != p[i]) return 0;
            }
            return 1;
        }
        """
        def run(self, r, p):
            rlen = len(r)
            plen = len(p)
            if rlen != plen:
                return 0
            for i in range(rlen):
                if r[i] != p[i]:
                    return 0
            return 1
            