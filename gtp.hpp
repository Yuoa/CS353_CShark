// (c) 2018 Yuoa.
// gtp.hpp

struct gtphdr {

    __u8 pn:1,
          s:1,
          e:1,
          t:1,
          pt:1,
          version:3;
    /*__u8 version:3, pt: 1, t:1, e:1, s:1, pn:1;*/
    __u8 msg_type;
    __u8 length_1;
    __u8 length_2;
    __u8 tei_1;
    __u8 tei_2;
    __u8 tei_3;
    __u8 tei_4;
    __u8 seq_1;
    __u8 seq_2;
    __u8 npdu;
    __u8 neht;

};
