/*
**  Copyright (c) 2013-2022 Mahmoud Fayed <msfclipper@yahoo.com> 
*/

#include "ring.h"

void ring_section ( const char *cTitle );
void ring_string_test ( void );

int main ( int argc, char *argv[] )
{
    ring_section("Hello!");
    printf( "Testing String Functions... \n" ) ;
    ring_section("Start of tests");
    ring_string_test();
    ring_section("End of tests");
    getchar();
}

void ring_section ( const char *cTitle )
{
    //ring_general_printline();
    printf( "%s\n",cTitle ) ;
    //ring_general_printline();
}

void ring_string_test ( void )
{
    #define nMaxValue 10
    String *mystr[nMaxValue]  ;
    int x  ;
    String *pString  ;
    for ( x = 0 ; x < nMaxValue ; x++ ) {
        mystr[x] = ring_string_new("Wow Really i like the c language so much");
        ring_string_print(mystr[x]);
    }
    for ( x = 0 ; x < nMaxValue ; x++ ) {
        mystr[x] = ring_string_delete(mystr[x]);
    }
    /* Test String Add */
    pString = ring_string_new("Hello ");
    ring_string_add(pString,"World");
    printf( "\nTest String Add , Output = %s\n",ring_string_get(pString) ) ;
    ring_string_add(pString," Welcome to the C programming language");
    printf( "\nTest String Add , Output = %s\n",ring_string_get(pString) ) ;
    ring_string_delete(pString);
    /* Test String to Lower */
    pString = ring_string_new("Welcome to my StrinG");
    printf( "Test string to lower \n" ) ;
    printf( "%s\n",ring_string_tolower(pString) ) ;
    ring_string_delete(pString);
}