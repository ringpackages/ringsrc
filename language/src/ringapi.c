/* Copyright (c) 2013-2023 Mahmoud Fayed <msfclipper@yahoo.com> */
#include "ring.h"
/* Support for C Functions */

RING_API void ring_vm_funcregister2 ( RingState *pRingState,const char *cStr, void (*pFunc)(void *) )
{
    List *pList  ;
    if ( pRingState->pRingCFunctions == NULL ) {
        pRingState->pRingCFunctions = ring_list_new_gc(pRingState,0);
    }
    pList = ring_list_newlist_gc(pRingState,pRingState->pRingCFunctions);
    ring_list_addstring_gc(pRingState,pList,cStr);
    ring_list_addfuncpointer_gc(pRingState,pList,pFunc);
}

RING_API void ring_vm_loadcfunctions ( RingState *pRingState )
{
    ring_vm_generallib_loadfunctions(pRingState);
    /* Load Modules */
    ring_vm_extension(pRingState);
}

int ring_vm_api_islist ( void *pPointer,int x )
{
    int nType  ;
    List *pList  ;
    VM *pVM  ;
    pVM = (VM *) pPointer ;
    pList = ring_list_getlist(RING_API_PARALIST,x) ;
    if ( ring_list_ispointer(pList,RING_VAR_VALUE) ) {
        nType = RING_API_GETPOINTERTYPE(x);
        if ( nType == RING_OBJTYPE_VARIABLE || nType == RING_OBJTYPE_LISTITEM ) {
            return 1 ;
        }
    }
    return 0 ;
}

RING_API List * ring_vm_api_getlist ( void *pPointer,int x )
{
    int nType  ;
    Item *pItem  ;
    List *pList  ;
    if ( RING_API_ISPOINTER(x) ) {
        nType = RING_API_GETPOINTERTYPE(x);
        if ( nType == RING_OBJTYPE_VARIABLE ) {
            pList = (List *) RING_API_GETPOINTER(x) ;
            return ring_list_getlist(pList,3) ;
        }
        else if ( nType == RING_OBJTYPE_LISTITEM ) {
            pItem = (Item *) RING_API_GETPOINTER(x) ;
            return ring_item_getlist(pItem) ;
        }
    }
    return NULL ;
}

RING_API void ring_vm_api_retlist ( void *pPointer,List *pList )
{
    ring_vm_api_retlist2(pPointer,pList,RING_OUTPUT_RETLIST);
}

RING_API List * ring_vm_api_newlist ( VM *pVM )
{
    List *pList  ;
    pList = ring_list_newlist_gc(pVM->pRingState,pVM->pActiveMem);
    return pList ;
}

RING_API void ring_vm_api_retcpointer2 ( void *pPointer,void *pGeneral,const char *cType, void (* pFreeFunc)(void *,void *) )
{
    List *pList  ;
    Item *pItem  ;
    /* Create the list */
    pList = RING_API_NEWLIST ;
    /* The variable value will be a list contains the pointer */
    ring_list_addpointer_gc(((VM *) pPointer)->pRingState,pList,pGeneral);
    /* Add the pointer type */
    ring_list_addstring_gc(((VM *) pPointer)->pRingState,pList,cType);
    /* Add the status number ( 0 = Not Copied ,1 = Copied  2 = Not Assigned yet) */
    ring_list_addint_gc(((VM *) pPointer)->pRingState,pList,RING_CPOINTERSTATUS_NOTASSIGNED);
    /* Set the Free Function */
    if ( pFreeFunc != NULL ) {
        pItem = ring_list_getitem(pList,RING_CPOINTER_POINTER);
        ring_vm_gc_setfreefunc(pItem,pFreeFunc);
    }
    RING_API_RETLIST(pList);
}

RING_API void * ring_vm_api_getcpointer ( void *pPointer,int x,const char *cType )
{
    List *pList  ;
    if ( RING_API_ISLISTORNULL(x) ) {
        pList = RING_API_GETLIST(x) ;
        if ( ring_list_ispointer(pList,1) ) {
            if ( ring_list_getpointer(pList,1) != NULL ) {
                if ( (strcmp(ring_list_getstring(pList,2),cType) == 0) || (((VM *) pPointer)->nIgnoreCPointerTypeCheck==1) ) {
                    /*
                    **  Check if the pointer is copied or not 
                    **  We check for 2 (not assigned) also, happens when f1 ( x , f2() ) and f2 return C pointer 
                    */
                    if ( (ring_list_getint(pList,3) == 0) || (ring_list_getint(pList,3) == 2) ) {
                        return ring_list_getpointer(pList,1) ;
                    }
                    ring_list_setpointer_gc(((VM *) pPointer)->pRingState,pList,1,NULL);
                    RING_API_ERROR(RING_API_NULLPOINTER);
                    return NULL ;
                }
                RING_API_ERROR(RING_API_BADPARATYPE);
                return NULL ;
            }
            else {
                if ( (strcmp(ring_list_getstring(pList,2),"NULLPOINTER") == 0) || (strcmp(ring_list_getstring(pList,2),cType) == 0) ) {
                    return NULL ;
                }
            }
            RING_API_ERROR(RING_API_NULLPOINTER);
            return NULL ;
        }
    }
    RING_API_ERROR(RING_API_NOTPOINTER);
    return NULL ;
}

RING_API void ring_vm_api_setcpointernull ( void *pPointer,int x )
{
    List *pList  ;
    pList = (List *) RING_API_GETLIST(x) ;
    /* Check pointer status ( 0 = Not copied , 1 = Copied ) */
    if ( ring_list_getint(pList,3) == RING_CPOINTERSTATUS_NOTCOPIED ) {
        ring_list_setpointer_gc(((VM *) pPointer)->pRingState,pList,1,NULL);
        return ;
    }
}

RING_API void * ring_vm_api_varptr ( void *pPointer,const char  *cStr,const char *cStr2 )
{
    VM *pVM  ;
    List *pList, *pActiveMem  ;
    Item *pItem  ;
    /*
    **  Usage 
    **  To get pointer to a ring variable value (pointer to double or int) i.e. int * or double * 
    **  We need this because some C Functions get int * or double * as parameter 
    */
    pVM = (VM *) pPointer ;
    /* Set the Active Scope */
    pActiveMem = pVM->pActiveMem ;
    pVM->pActiveMem = ring_list_getlist(pVM->pMem,ring_list_getsize(pVM->pMem)-1);
    if ( ring_vm_findvar(pVM, cStr ) == 0 ) {
        /* Restore the Active Scope */
        pVM->pActiveMem = pActiveMem ;
        RING_API_ERROR(RING_VM_ERROR_NOTVARIABLE);
        return NULL ;
    }
    /* Restore the Active Scope */
    pVM->pActiveMem = pActiveMem ;
    pList = (List *) RING_VM_STACK_READP ;
    RING_VM_STACK_POP ;
    if ( ring_list_getint(pList,RING_VAR_TYPE) == RING_VM_NUMBER ) {
        pItem = ring_list_getitem(pList,RING_VAR_VALUE);
        if ( strcmp(cStr2,"double") == 0 ) {
            return &(pItem->data.dNumber) ;
        }
        else if ( strcmp(cStr2,"int") == 0 ) {
            pItem->data.iNumber = (int) pItem->data.dNumber ;
            return &(pItem->data.iNumber) ;
        }
        else if ( strcmp(cStr2,"float") == 0 ) {
            pItem->data.fNumber = (float) pItem->data.dNumber ;
            return &(pItem->data.fNumber) ;
        }
    }
    else if ( ring_list_getint(pList,RING_VAR_TYPE) == RING_VM_STRING ) {
        pItem = ring_list_getitem(pList,RING_VAR_VALUE);
        return pItem->data.pString->cStr ;
    }
    return NULL ;
}

RING_API void ring_vm_api_varvalue ( void *pPointer,const char  *cStr,int nType )
{
    VM *pVM  ;
    List *pList, *pActiveMem  ;
    Item *pItem  ;
    /*
    **  Usage 
    **  Convert the variable value from int to double 
    **  When we pass int * for Ring Variable Value to a C Function 
    **  We need to convert again from int to double, because Ring uses double 
    */
    pVM = (VM *) pPointer ;
    /* Set the Active Scope */
    pActiveMem = pVM->pActiveMem ;
    pVM->pActiveMem = ring_list_getlist(pVM->pMem,ring_list_getsize(pVM->pMem)-1);
    if ( ring_vm_findvar(pVM, cStr ) == 0 ) {
        /* Restore the Active Scope */
        pVM->pActiveMem = pActiveMem ;
        RING_API_ERROR(RING_VM_ERROR_NOTVARIABLE);
        return ;
    }
    /* Restore the Active Scope */
    pVM->pActiveMem = pActiveMem ;
    pList = (List *) RING_VM_STACK_READP ;
    RING_VM_STACK_POP ;
    if ( ring_list_getint(pList,RING_VAR_TYPE) == RING_VM_NUMBER ) {
        pItem = ring_list_getitem(pList,RING_VAR_VALUE);
        if ( nType == 1 ) {
            pItem->data.dNumber = (double) pItem->data.iNumber ;
        }
        else {
            pItem->data.dNumber = (double) pItem->data.fNumber ;
        }
    }
}

RING_API void ring_list_addcpointer ( List *pList,void *pGeneral,const char *cType )
{
    List *pList2  ;
    /* create sub list */
    pList2 = ring_list_newlist(pList);
    /* The variable value will be a list contains the pointer */
    ring_list_addpointer(pList2,pGeneral);
    /* Add the pointer type */
    ring_list_addstring(pList2,cType);
    /* Add the status number ( 0 = Not Copied ,1 = Copied  2 = Not Assigned yet) */
    ring_list_addint(pList2,2);
}

RING_API int ring_vm_api_iscpointerlist ( List *pList )
{
    return ring_list_iscpointerlist(pList) ;
}

RING_API int ring_vm_api_iscpointer ( void *pPointer,int x )
{
    if ( RING_API_ISLISTORNULL(x) ) {
        return ring_vm_api_iscpointerlist(RING_API_GETLIST(x)) ;
    }
    return 0 ;
}

RING_API int ring_vm_api_isobject ( void *pPointer,int x )
{
    if ( RING_API_ISLISTORNULL(x) ) {
        return ring_vm_oop_isobject(RING_API_GETLIST(x)) ;
    }
    return 0 ;
}

RING_API int ring_vm_api_cpointercmp ( List *pList,List *pList2 )
{
    return ring_list_cpointercmp(pList,pList2) ;
}

RING_API int ring_vm_api_ispointer ( void *pPointer,int x )
{
    List *pList, *pList2  ;
    VM *pVM  ;
    Item *pItem  ;
    pVM = (VM *) pPointer ;
    pList = ring_list_getlist(RING_API_PARALIST,x) ;
    if ( ring_list_ispointer(pList,RING_VAR_VALUE) ) {
        return 1 ;
    }
    else if ( ring_list_isstring(pList,RING_VAR_VALUE) ) {
        /* Treat NULL Strings as NULL Pointers - so we can use NULL instead of NULLPOINTER() */
        if ( (strcmp(ring_list_getstring(pList,RING_VAR_VALUE),"") == 0) || (strcmp(ring_list_getstring(pList,RING_VAR_VALUE),"NULL") == 0) ) {
            /* Create the list for the NULL Pointer */
            ring_list_setint_gc(pVM->pRingState,pList,RING_VAR_TYPE,RING_VM_POINTER);
            pList2 = RING_API_NEWLIST ;
            pItem = ring_list_getitem(pVM->pActiveMem,ring_list_getsize(pVM->pActiveMem));
            /* Increase the References count for the item */
            ring_vm_gc_newitemreference(pItem);
            ring_list_setpointer_gc(pVM->pRingState,pList,RING_VAR_VALUE,pItem);
            ring_list_setint_gc(pVM->pRingState,pList,RING_VAR_PVALUETYPE,RING_OBJTYPE_LISTITEM);
            /* The variable value will be a list contains the pointer */
            ring_list_addpointer_gc(pVM->pRingState,pList2,NULL);
            /* Add the pointer type */
            ring_list_addstring_gc(pVM->pRingState,pList2,"NULLPOINTER");
            /* Add the status number ( 0 = Not Copied ,1 = Copied  2 = Not Assigned yet) */
            ring_list_addint_gc(pVM->pRingState,pList2,RING_CPOINTERSTATUS_NOTASSIGNED);
            return 1 ;
        }
    }
    return 0 ;
}

RING_API void * ring_vm_api_getcpointer2pointer ( void *pPointer,int x,const char *cType )
{
    List *pList  ;
    Item *pItem  ;
    if ( RING_API_ISLISTORNULL(x) ) {
        pList = RING_API_GETLIST(x) ;
        if ( ring_list_ispointer(pList,1) ) {
            if ( ring_list_getpointer(pList,1) != NULL ) {
                if ( (strcmp(ring_list_getstring(pList,2),cType) == 0) || (((VM *) pPointer)->nIgnoreCPointerTypeCheck==1) ) {
                    /*
                    **  Check if the pointer is copied or not 
                    **  We check for 2 (not assigned) also, happens when f1 ( x , f2() ) and f2 return C pointer 
                    */
                    if ( (ring_list_getint(pList,3) == 0) || (ring_list_getint(pList,3) == 2) ) {
                        pItem = ring_list_getitem(pList,1);
                        return & (pItem->data.pPointer) ;
                    }
                    ring_list_setpointer_gc(((VM *) pPointer)->pRingState,pList,1,NULL);
                    RING_API_ERROR(RING_API_NULLPOINTER);
                    return NULL ;
                }
                RING_API_ERROR(RING_API_BADPARATYPE);
                return NULL ;
            }
            else {
                if ( strcmp(ring_list_getstring(pList,2),"NULLPOINTER") == 0 ) {
                    return NULL ;
                }
            }
            RING_API_ERROR(RING_API_NULLPOINTER);
            return NULL ;
        }
    }
    RING_API_ERROR(RING_API_NOTPOINTER);
    return NULL ;
}

RING_API void ring_list_addcpointer_gc ( void *pState,List *pList,void *pGeneral,const char *cType )
{
    List *pList2  ;
    /* create sub list */
    pList2 = ring_list_newlist_gc(pState,pList);
    /* The variable value will be a list contains the pointer */
    ring_list_addpointer_gc(pState,pList2,pGeneral);
    /* Add the pointer type */
    ring_list_addstring_gc(pState,pList2,cType);
    /* Add the status number ( 0 = Not Copied ,1 = Copied  2 = Not Assigned yet) */
    ring_list_addint_gc(pState,pList2,2);
}

RING_API void ring_vm_api_retcpointer ( void *pPointer,void *pGeneral,const char *cType )
{
    ring_vm_api_retcpointer2(pPointer,pGeneral,cType,NULL);
}

RING_API void ring_vm_api_retlist2 ( void *pPointer,List *pList,int nRef )
{
    int nType  ;
    List *pRealList,*pTempMem,*pVariableList, *pObjectVariable  ;
    VM *pVM  ;
    pVM = (VM *) pPointer ;
    /* Check Output Mode */
    if ( nRef == RING_OUTPUT_RETNEWREF ) {
        /* Check if we are creating a Reference before assignment, i.e. Ref(List(nSize)) */
        if ( ring_list_iscopybyref(pList) || ring_list_isdontrefagain(pList) ) {
            nRef = RING_OUTPUT_RETLISTBYREF ;
        }
        /* Check lDontRef Flag */
        if ( ring_list_isdontref(pList) ) {
            /* Reset the DontRef Flag to avoid reusage in wrong scope */
            ring_list_disabledontref(pList);
            /* Take in mind ref(ref(ref(new obj))) */
            ring_list_enabledontrefagain(pList);
            pVM->lDontMoveToPrevScope = ring_vm_oop_isobject(pList) ;
            /* Keep the same object (Ref() parameter) on the Stack (i.e. Return para. as output) */
            RING_VM_STACK_PUSH ;
            return ;
        }
    }
    if ( nRef == RING_OUTPUT_RETNEWREF ) {
        pTempMem = NULL ;
    }
    else {
        pTempMem = ring_vm_prevtempmem(pVM);
    }
    /* Create the container variable */
    pVariableList = ring_vm_newvar2(pVM,RING_TEMP_VARIABLE,pTempMem);
    ring_list_setint_gc(((VM *) pPointer)->pRingState,pVariableList,RING_VAR_TYPE,RING_VM_LIST);
    ring_list_setlist_gc(((VM *) pPointer)->pRingState,pVariableList,RING_VAR_VALUE);
    pRealList = ring_list_getlist(pVariableList,RING_VAR_VALUE);
    /* Copy the list */
    if ( nRef == RING_OUTPUT_RETLIST ) {
        /* Used by RING_API_RETLIST */
        ring_vm_list_copy((VM *) pPointer,pRealList,pList);
    }
    else if ( nRef == RING_OUTPUT_RETLISTBYREF ) {
        /* Used by RING_API_RETLISTBYREF  (i.e. List() function implementation) */
        ring_list_enablecopybyref(pList);
        ring_list_swaptwolists(pRealList,pList);
    }
    else {
        /* Used by RING_API_RETNEWREF (i.e. Ref()/Reference() function implementation) */
        pVariableList = ring_list_newref_gc(((VM *) pPointer)->pRingState,pVariableList,pList);
        pVM->lDontMoveToPrevScope = 1 ;
    }
    if ( (nRef == RING_OUTPUT_RETLIST) || (nRef == RING_OUTPUT_RETLISTBYREF) ) {
        /* Update self object pointer */
        if ( ring_vm_oop_isobject(pRealList) ) {
            ring_vm_oop_updateselfpointer(pVM,pRealList,RING_OBJTYPE_VARIABLE,pVariableList);
        }
    }
    RING_API_PUSHPVALUE(pVariableList);
    RING_API_OBJTYPE = RING_OBJTYPE_VARIABLE ;
}

RING_API void ring_vm_api_intvalue ( void *pPointer,const char  *cStr )
{
    ring_vm_api_varvalue(pPointer,cStr,1);
}

RING_API void ring_vm_api_floatvalue ( void *pPointer,const char  *cStr )
{
    ring_vm_api_varvalue(pPointer,cStr,2);
}

int ring_vm_api_islistornull ( void *pPointer,int x )
{
    int nType  ;
    if ( RING_API_ISPOINTER(x) ) {
        nType = RING_API_GETPOINTERTYPE(x);
        if ( nType == RING_OBJTYPE_VARIABLE || nType == RING_OBJTYPE_LISTITEM ) {
            return 1 ;
        }
    }
    return 0 ;
}
