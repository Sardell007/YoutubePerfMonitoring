set hour=%time:~0,2%
if "%hour:~0,1%"==" " set hour=0%hour:~1,1%
set datetimef=%date:~-4%_%date:~3,2%_%date:~0,2%__%hour%_%time:~3,2%_%time:~6,2%

FOR /L %%A IN (2,1,27) DO (
    python assign.py --url "https://www.youtube.com/watch?v=MIhsx4Up9i8&list=PLtMv0AJo8LlIax9mNM8YDiIGh3bdV-UuV&index=%%A" --output_pref "563499_%datetimef%"
)