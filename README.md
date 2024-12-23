Программа предназначена для мониторинга и управления поведением целевого процесса в операционной системе Windows. Она позволяет перехватывать вызовы определённых API-функций, таких как CreateFileW, FindFirstFileW и FindNextFileW, и логировать их использование. Кроме того, программа может скрывать указанные файлы, делая их невидимыми для целевого процесса. Это достигается посредством инъекции DLL (MonitorHook.dll) в целевой процесс и использования механизма перехвата функций через таблицу импорта (IAT).

Сборка Программы
1. Компиляция: Скомпилируйте Monitor.cpp и MonitorHook.cpp с использованием подходящего компилятора для Windows (например, Visual Studio).
2. Создание DLL: Убедитесь, что MonitorHook.cpp компилируется как DLL (MonitorHook.dll).
3. Размещение DLL: Поместите MonitorHook.dll в ту же директорию, что и исполняемый файл Monitor.exe, или укажите полный путь к DLL при запуске.

Запуск Программы
Используйте командную строку для запуска Monitor.exe с необходимыми аргументами. Ниже приведены примеры использования:

Указание Процесса по Имени:
    
    Monitor.exe -name TargetProcess.exe -func CreateFileW -hide secret.txt
Описание: Мониторит вызовы CreateFileW в процессе TargetProcess.exe и скрывает файл secret.txt от этого процесса.

Указание Процесса по PID:

    Monitor.exe -pid 1234 -func FindFirstFileW

Описание: Мониторит вызовы FindFirstFileW в процессе с PID 1234.
    
Мониторинг Нескольких Функций и Скрытие Нескольких Файлов:
Программа в текущей реализации поддерживает мониторинг одной функции и скрытие одного файла за раз. Для расширения функционала может потребоваться модификация кода.

Аргументы Командной Строки

    -pid <Process ID>: Указывает идентификатор целевого процесса.
    -name <Process Name>: Указывает имя исполняемого файла целевого процесса.
    -func <Function Name>: Указывает имя функции для мониторинга (например, CreateFileW).
    -hide <File Name>: Указывает имя файла для скрытия от целевого процесса.

Важно: Необходимо указать либо -pid, либо -name для определения целевого процесса. Также необходимо указать хотя бы один из параметров -func или -hide.
Пример Полного Использования

Допустим, вы хотите мониторить вызовы CreateFileW и скрыть файл config.ini от процесса ExampleApp.exe. Для этого выполните следующую команду:

    Monitor.exe -name ExampleApp.exe -func CreateFileW -hide config.ini
