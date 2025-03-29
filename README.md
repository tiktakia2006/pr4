# ПРАКТИЧНА РОБОТА 4

## ЗАВДАННЯ 1

## Умова
Скільки пам’яті може виділити malloc(3) за один виклик?
Параметр malloc(3) є цілим числом типу даних size_t, тому логічно максимальне число, яке можна передати як параметр malloc(3), 
— це максимальне значення size_t на платформі (sizeof(size_t)). У 64-бітній Linux size_t становить 8 байтів, тобто 8 * 8 = 64 біти. 
Відповідно, максимальний обсяг пам’яті, який може бути виділений за один виклик malloc(3), дорівнює 2^64. Спробуйте запустити код на 
x86_64 та x86. Чому теоретично максимальний обсяг складає 8 ексабайт, а не 16?

## Код до завдання
```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    size_t max_size = (size_t) -1;
    void *ptr = malloc(max_size);

    if (ptr == NULL) {
        printf("Memory allocation failed\n");
        return 1;
    } else {
        printf("Memory successfully allocated\n");
        free(ptr);
    }

    return 0;
}
```

## Опис програми
Функція malloc(3) може виділити пам'ять до максимального значення типу
size_t, яке зазвичай дорівнює 2^64 - 1 байт на 64-бітній системі, що відповідає
16 ексабайтам. Проте реальний ліміт виділення пам'яті значно менший через
обмеження операційної системи, апаратного забезпечення та доступної
віртуальної пам'яті. Навіть на 64-бітних системах не вдається виділити таку
величезну кількість пам'яті, і, як правило, максимум складає близько 8
ексабайт. Це пов'язано з обмеженнями на адресацію пам'яті, які застосовуються
в операційних системах.

## Результати програми
![image](https://github.com/user-attachments/assets/fc619e95-40f9-4a54-a1c7-456267cc9a44)


## ЗАВДАННЯ 2

## Умова
Що станеться, якщо передати malloc(3) від’ємний аргумент? Напишіть тестовий випадок, який обчислює кількість виділених байтів за 
формулою num = xa * xb. Що буде, якщо num оголошене як цілочисельна змінна зі знаком, а результат множення призведе до переповнення? 
Як себе поведе malloc(3)? Запустіть програму на x86_64 і x86.

## Код до завдання
```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    int xa = 1000000000;
    int xb = 3000;
    int num = xa * xb;

    if (num < 0) {
        printf("Multiplication overflow occurred\n");
    } else {
        void *ptr = malloc(num);
        if (ptr == NULL) {
            printf("Memory allocation failed\n");
        } else {
            printf("Memory successfully allocated\n");
            free(ptr);
        }
    }

    return 0;
}
```

## Опис програми
У моєму коді, при множенні xa і xb, можливе переповнення змінної int, що
може зробити значення num від'ємним. Якщо передати таке значення у malloc(),
функція не зможе виділити пам’ять і поверне NULL. Однак, у моєму тестуванні
програма вивела Memory successfully allocated;, що означає, що переповнення
не відбулося або система автоматично перетворила типи при виклику malloc().
На 32-бітній архітектурі переповнення могло б проявитися швидше через
менший розмір змінних. Це показує, що слід бути обережним із множенням
великих чисел при виділенні пам’яті

## Результати програми
![image](https://github.com/user-attachments/assets/ecd47375-48a6-40f0-8d25-99ed9c474820)


## ЗАВДАННЯ 3

## Умова
Що станеться, якщо використати malloc(0)? Напишіть тестовий випадок, у якому malloc(3) повертає NULL 
або вказівник, що не є NULL, і який можна передати у free(). Відкомпілюйте та запустіть через ltrace. 
Поясніть поведінку програми.

## Код до завдання
```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    void *ptr = malloc(0);

    if (ptr == NULL) {
        printf("malloc(0) returned NULL\n");
    } else {
        printf("malloc(0) returned a valid pointer\n");
        free(ptr);
    }

    return 0;
}
```

## Опис програми
У моєму коді виклик malloc(0) повернув дійсний вказівник, а не NULL, що
видно у виводі ltrace. Це підтверджує, що malloc(0) може виділяти нуль байтів і
при цьому повертати не NULL, а спеціальний вказівник, який можна передати у
free(). Реалізація malloc у glibc часто поводиться саме так: виділяє невелику
керовану область або повторно використовує системні структури. Оскільки
вказівник був дійсним, виклик free(ptr) успішно виконав звільнення, не
спричинивши помилок. Таким чином, поведінка malloc(0) залежить від
конкретної реалізації malloc, і її слід перевіряти перед використанням.

## Результати програми
![image](https://github.com/user-attachments/assets/41b1f397-6f65-4455-aa35-0748a55af95c)



## ЗАВДАННЯ 4

## Умова
Чи є помилки у такому коді?
void *ptr = NULL;
while (<some-condition-is-true>) {
    if (!ptr)
        ptr = malloc(n);
    [... <використання 'ptr'> ...]
    free(ptr);
}

Напишіть тестовий випадок, який продемонструє проблему та правильний варіант коду.


## Код до завдання
```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    void *ptr = malloc(16);
    int i = 0;

    if (!ptr) {
        printf("Memory allocation failed\n");
        return 1;
    }

    while (i < 5) {
        printf("Using allocated memory at: %p\n", ptr);
        i++;
    }

    free(ptr);

    return 0;
}
```

## Опис програми
Так, у цьому коді є серйозна логічна помилка – пам’ять виділяється за
допомогою malloc(n), але у кожній ітерації циклу вона одразу звільняється
через free(ptr), навіть якщо ptr ще потрібен. Це може призвести до використання
звільненої пам’яті (use-after-free) або витоків пам’яті, якщо виділення
відбуватиметься повторно без оновлення ptr

## Результати програми
![image](https://github.com/user-attachments/assets/8703d2f4-b9dc-4554-b435-7f97f92af451)


## ЗАВДАННЯ 5

## Умова
Що станеться, якщо realloc(3) не зможе виділити пам’ять? Напишіть тестовий випадок, що демонструє цей сценарій.

## Код до завдання
```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    size_t huge_size = (size_t)-1;
    void *ptr = malloc(10);

    if (!ptr) {
        printf("Initial allocation failed\n");
        return 1;
    }

    void *new_ptr = realloc(ptr, huge_size);

    if (!new_ptr) {
        printf("Realloc failed: not enough memory\n");
        free(ptr);
    } else {
        printf("Realloc succeeded unexpectedly\n");
        free(new_ptr);
    }

    return 0;
}
```

## Опис програми
Якщо realloc(3) не зможе виділити пам’ять, він поверне NULL, але початковий
вказівник залишиться дійсним. У моєму коді realloc(3) намагався виділити
величезний обсяг пам’яті, що перевищує можливості системи, тому він
повернув NULL. Важливо перевіряти результат realloc(3), щоб уникнути втрати
початкового вказівника та потенційного витоку пам’яті. У такому випадку
потрібно вручну звільнити старий блок пам’яті через free(ptr).

## Результати програми
![image](https://github.com/user-attachments/assets/619e9a48-fc8f-442c-ad22-adee9015039c)



## ЗАВДАННЯ 6

## Умова
Якщо realloc(3) викликати з NULL або розміром 0, що станеться? Напишіть тестовий випадок

## Код до завдання
```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    void *ptr = NULL;

    ptr = realloc(ptr, 10);
    if (ptr != NULL) {
        printf("Memory allocated with size 10\n");
    }

    ptr = realloc(ptr, 0);
    if (ptr == NULL) {
        printf("Memory freed with size 0\n");
    }

    if (ptr != NULL) {
        free(ptr);
    }

    return 0;
}
```

## Опис програми
Якщо realloc() викликається з NULL, то це поводиться як malloc() і виділяє нову
пам'ять. Якщо передати розмір 0, realloc() звільняє пам';ять, еквівалентно
виклику free(). У моєму випадку пам'ять була спочатку виділена розміром 10
байт, а потім звільнена при виклику realloc() з розміром 0.

## Результати програми
![image](https://github.com/user-attachments/assets/5b59ef66-2cbc-4ba6-b4b5-7a2d4bb02f6c)


## ЗАВДАННЯ 7

## Умова
Перепишіть наступний код, використовуючи reallocarray(3):
struct sbar *ptr, *newptr;
ptr = calloc(1000, sizeof(struct sbar));
newptr = realloc(ptr, 500*sizeof(struct sbar));

Порівняйте результати виконання з використанням ltrace.

## Код до завдання
```c
#include <stdio.h>
#include <stdlib.h>

struct sbar {
    int data;
};

int main() {
    struct sbar *ptr, *newptr;

    ptr = reallocarray(NULL, 1000, sizeof(struct sbar));
    newptr = reallocarray(ptr, 500, sizeof(struct sbar));

    if (newptr != NULL) {
        printf("Memory successfully allocated and resized\n");
        free(newptr);
    } else {
        printf("Memory allocation failed\n");
    }

    return 0;
}
```

## Опис програми
При порівнянні результатів з використанням ltrace, видно, що замість
стандартних malloc та realloc, використовується reallocarray, який одразу
приймає кількість елементів та їхній розмір. Перший виклик reallocarray з 1000
елементів та розміром 4 байти дає правильне виділення пам'яті, а другий
виклик зменшує кількість елементів до 500, зберігаючи ту ж саму адресу
пам'яті. Це підтверджує, що reallocarray працює аналогічно, але з кращою
перевіркою помилок при переповненні пам'яті.

## Результати програми
![image](https://github.com/user-attachments/assets/23fcef3f-d51a-4fcc-98db-606967e7d000)



## ЗАВДАННЯ 8 (ВАРІАНТ 13)

## Умова
Використайте mallopt() для налаштування malloc та перевірте ефект.

## Код до завдання
```c
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

int main() {
    mallopt(M_MXFAST, 1024 * 1024);

    void *ptr1 = malloc(100);
    void *ptr2 = malloc(5000);
    void *ptr3 = malloc(10000);

    if (ptr1 == NULL || ptr2 == NULL || ptr3 == NULL) {
        printf("Memory allocation failed\n");
    } else {
        printf("Memory successfully allocated\n");

        printf("Allocated memory at ptr1: %p\n", ptr1);
        printf("Allocated memory at ptr2: %p\n", ptr2);
        printf("Allocated memory at ptr3: %p\n", ptr3);

        free(ptr1);
        free(ptr2);
        free(ptr3);
    }

    return 0;
}
```

## Опис програми
Використання функції mallopt() для налаштування параметра M_MXFAST
дозволяє змінити розмір блоку пам'яті, який може бути виділений за допомогою
функції malloc() без звернення до системи. У даному випадку параметр
M_MXFAST був встановлений на значення 1 МБ, що дозволило швидко
виділити пам'ять для різних обсягів без затримок. Це покращує ефективність
виділення пам'яті для малих запитів

## Результати програми
![image](https://github.com/user-attachments/assets/2d45762c-166a-49bf-9fd8-01b32f1f43c3)


