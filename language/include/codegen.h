/* Copyright (c) 2013-2023 Mahmoud Fayed <msfclipper@yahoo.com> */
#ifndef ring_codegen_h
    #define ring_codegen_h
    /*
    **  Data 
    **  Intermediate Code 
    */
    typedef enum IC_OPERATIONS {
        /* General */
        ICO_NEWLINE=0 ,
        ICO_FILENAME ,
        ICO_PRINT ,
        ICO_NEWCLASS ,
        ICO_NEWFUNC ,
        ICO_DUPLICATE ,
        ICO_NEWOBJ ,
        ICO_GIVE ,
        ICO_PRIVATE ,
        ICO_NEWLABEL ,
        /* Control Structure */
        ICO_JUMP ,
        ICO_JUMPZERO ,
        ICO_JUMPONE ,
        ICO_JUMPFOR ,
        ICO_JUMPZERO2 ,
        ICO_JUMPONE2 ,
        ICO_PUSHNULLTHENJUMP ,
        /* Variables */
        ICO_LOADADDRESS ,
        ICO_ASSIGNMENT ,
        ICO_LOADSUBADDRESS ,
        ICO_LOADINDEXADDRESS ,
        ICO_LOADAPUSHV ,
        /* Comparison operators */
        ICO_EQUAL ,
        ICO_LESS ,
        ICO_GREATER ,
        ICO_NOTEQUAL ,
        ICO_LESSEQUAL ,
        ICO_GREATEREQUAL ,
        /* Data */
        ICO_PUSHC ,
        ICO_PUSHN ,
        ICO_PUSH2N ,
        ICO_PUSH3N ,
        ICO_PUSH4N ,
        ICO_PUSHV ,
        ICO_PUSHP ,
        ICO_PUSHPV ,
        ICO_PUSHPLOCAL ,
        /* Arithmetic */
        ICO_SUM ,
        ICO_SUB ,
        ICO_MUL ,
        ICO_DIV ,
        ICO_MOD ,
        ICO_NEG ,
        ICO_INC ,
        ICO_INCP ,
        ICO_POW ,
        /* Functions/Methods */
        ICO_LOADFUNC ,
        ICO_CALL ,
        ICO_RETURN ,
        ICO_RETNULL ,
        ICO_RETFROMEVAL ,
        ICO_RETITEMREF ,
        /* Lists */
        ICO_LISTSTART ,
        ICO_LISTITEM ,
        ICO_LISTEND ,
        /* Logic */
        ICO_AND ,
        ICO_OR ,
        ICO_NOT ,
        /* More */
        ICO_FREESTACK ,
        ICO_BLOCKFLAG ,
        ICO_FUNCEXE ,
        ICO_ENDFUNCEXE ,
        ICO_BYE ,
        ICO_EXITMARK ,
        ICO_POPEXITMARK ,
        ICO_EXIT ,
        ICO_INCJUMP ,
        ICO_INCPJUMP ,
        ICO_TRY ,
        ICO_DONE ,
        ICO_RANGE ,
        ICO_LOADMETHOD ,
        ICO_SETSCOPE ,
        ICO_AFTERCALLMETHOD ,
        ICO_BRACESTART ,
        ICO_BRACEEND ,
        ICO_LOADFUNCP ,
        ICO_FREELOADASCOPE ,
        /* Loop */
        ICO_LOOP ,
        /* Loop optimization in functions (local scope) */
        ICO_INCLPJUMP ,
        /* Packages */
        ICO_PACKAGE ,
        ICO_IMPORT ,
        /* Property */
        ICO_SETPROPERTY ,
        ICO_NOOP ,
        ICO_AFTERCALLMETHOD2 ,
        /* Other */
        ICO_SETREFERENCE ,
        ICO_KILLREFERENCE ,
        ICO_ASSIGNMENTPOINTER ,
        ICO_BEFOREEQUAL ,
        ICO_PLUSPLUS ,
        ICO_MINUSMINUS ,
        /* Bitwise Operators */
        ICO_BITAND ,
        ICO_BITOR ,
        ICO_BITNOT ,
        ICO_BITXOR ,
        ICO_BITSHL ,
        ICO_BITSHR ,
        /* For Loop Step */
        ICO_STEPNUMBER ,
        ICO_POPSTEP ,
        ICO_LOADAFIRST ,
        ICO_INCPJUMPSTEP1 ,
        ICO_INCLPJUMPSTEP1 ,
        /* Anonymous Functions */
        ICO_ANONYMOUS ,
        /* Class Init */
        ICO_CALLCLASSINIT ,
        /* Custom Global Scope */
        ICO_NEWGLOBALSCOPE ,
        ICO_ENDGLOBALSCOPE ,
        ICO_SETGLOBALSCOPE ,
        /* Temp Lists */
        ICO_FREETEMPLISTS ,
        /* Better Performance */
        ICO_LEN ,
        ICO_SETOPCODE 
    } IC_OPERATIONS ;
    /* Operations Text (Array) */
    static const char * RING_IC_OP[] = {"NewLine","FileName","Print","Class","Func","Dup","New","Give","Private","NewLabel", 
    
    "Jump","JumpZ","Jump1","JumpFOR","JZ2","J12","PUSHNULLTHENJUMP","LoadA","Assignment","LoadSA","LoadIA","LoadAPushV","==","<",">","!=","<=",">=", 
    
    "PushC","PushN","Push2N","Push3N","Push4N","PushV","PushP","PushPV","PushPLocal", "SUM","SUB","MUL","DIV","MOD","Negative","Inc","IncP","POW", 
    
    "LoadFunc","Call", "Return","ReturnNull","RetFromEval","RetItemRef","ListStart","ListItem","ListEnd","And","Or","Not","FreeStack", 
    
    "BlockFlag","FuncExE","EndFuncExe","Bye","ExitMark","POPExitMark","Exit","IncJump","IncPJump", 
    
    "Try","Done","Range","LoadMethod","SetScope","AfterCallMethod", 
    
    "BraceStart","BraceEnd","LoadFuncP","FreeLoadAScope","Loop","IncLPJump","Package","Import", 
    
    "SetProperty","NoOperation","AfterCallMethod2","SetReference","KillReference","AssignmentPointer","BeforeEqual","++","--", 
    
    "BITAND","BITOR","BITNOT","BITXOR","BITSHL","BITSHR","StepNumber","POPStep","LoadAFirst", 
    
    "INCPJUMPSTEP1","INCLPJUMPSTEP1","ANONYMOUS","CallClassInit", 
    
    "NewGlobalScope","EndGlobalScope","SetGlobalScope","FreeTempLists","Len","SetOPCode"} ;
    /* Macro */
    #define RING_PARSER_ICG_GOTOLASTOP pParser->ActiveGenCodeList = ring_list_getlist(pParser->GenCode,ring_list_getsize(pParser->GenCode))
    #define ring_parser_icg_newlabel(x) ( ring_list_getsize(x->GenCode) + 1 + pParser->pRingState->nInstructionsCount)
    #define ring_parser_icg_getlastoperation(pParser) ring_list_getint(pParser->ActiveGenCodeList,1)
    #define ring_parser_icg_setlastoperation(pParser,x) ring_list_setint_gc(pParser->pRingState,pParser->ActiveGenCodeList,1,x)
    #define ring_parser_icg_instructionscount(pParser) ring_list_getsize(pParser->GenCode) + pParser->pRingState->nInstructionsCount
    #define ring_parser_icg_instructionslistsize(pParser) ring_list_getsize(pParser->GenCode)
    #define ring_parser_icg_getoperationlist(pParser,x) ring_list_getlist(pParser->GenCode,x)
    #define RING_PARSER_ICG_OPERATIONCODE 1
    #define ring_parser_icg_getoperationbeforelastoperation(pParser) ring_list_getint(ring_parser_icg_getoperationlist(pParser,ring_list_getsize(pParser->GenCode)-1),RING_PARSER_ICG_OPERATIONCODE)
    #define ring_parser_icg_getoperationatpos(pParser,x) ring_list_getint(ring_parser_icg_getoperationlist(pParser,x),RING_PARSER_ICG_OPERATIONCODE)
    #define ring_parser_icg_getoperandint(pParser,x) ring_list_getint(pParser->ActiveGenCodeList,x)
    #define ring_parser_icg_getoperanddouble(pParser,x) ring_list_getdouble(pParser->ActiveGenCodeList,x)
    #define RING_PARSER_ICG_PARENTCLASSPOS 4
    #define RING_PARSER_ICG_INSTRUCTIONSLISTTYPE List
    #define ring_parser_icg_setoperationatpos(pParser,x,y) ring_list_setint(ring_parser_icg_getoperationlist(pParser,x),RING_PARSER_ICG_OPERATIONCODE,y)
    /*
    **  Functions 
    **  Generate Intermediate Code 
    */

    void ring_parser_icg_newoperation ( Parser *pParser , IC_OPERATIONS opcode ) ;

    void ring_parser_icg_newoperand ( Parser *pParser , const char *cStr ) ;

    void ring_parser_icg_addtooperand ( Parser *pParser , const char *cStr ) ;

    void ring_parser_icg_newoperandint ( Parser *pParser , int nValue ) ;

    void ring_parser_icg_newoperanddouble ( Parser *pParser , double nValue ) ;

    void ring_parser_icg_newoperandpointer ( Parser *pParser , void *pValue ) ;

    List * ring_parser_icg_getactiveoperation ( Parser *pParser ) ;

    void ring_parser_icg_addoperand ( Parser *pParser ,List *pList , const char *cStr ) ;

    void ring_parser_icg_addoperandint ( Parser *pParser ,List *pList , int nValue ) ;

    void ring_parser_icg_addoperandpointer ( Parser *pParser ,List *pList , void *pValue ) ;

    void ring_parser_icg_deletelastoperation ( Parser *pParser ) ;

    void ring_parser_icg_duplicate ( Parser *pParser,int nStart,int nEnd ) ;

    int ring_parser_icg_newlabel2 ( Parser *pParser ) ;

    void ring_parser_icg_insertoperation ( Parser *pParser , int nPos , IC_OPERATIONS opcode ) ;

    void ring_parser_icg_setopcode ( Parser *pParser ,List *pList , int nValue ) ;

    void ring_parser_icg_deleteoperand ( Parser *pParser , int nPos ) ;
    /* Specific Instructions */

    void ring_parser_icg_loadfunction ( Parser *pParser,const char *cFunctionName ) ;

    void ring_parser_icg_loadaddress ( Parser *pParser,const char *cVariableName ) ;

    void ring_parser_icg_loadaddressassignmentpos ( Parser *pParser,List *pLoadAPos,int nPos ) ;

    void ring_parser_icg_loadaddresstoloadfunction ( Parser *pParser ) ;

    void ring_parser_icg_freestack ( Parser *pParser ) ;

    void ring_parser_icg_newline ( Parser *pParser,int nLine ) ;

    char * ring_parser_icg_parentclassname ( Parser *pParser ) ;

    char * ring_parser_icg_newpackagename ( Parser *pParser,List *pPos ) ;

    void ring_parser_icg_pushn ( Parser *pParser,double nValue ) ;

    void ring_parser_icg_beforeequal ( Parser *pParser,int nBeforeEqual ) ;
    /* Show the Intermediate Code */

    void ring_parser_icg_showoutput ( List *pListGenCode ) ;
#endif
