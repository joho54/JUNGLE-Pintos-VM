/* Recursively forks until the child fails to fork.
   We expect that at least 28 copies can run.
   
   We count how many children your kernel was able to execute
   before it fails to start a new process.  We require that,
   if a process doesn't actually get to start, exec() must
   return -1, not a valid PID.

   We repeat this process 10 times, checking that your kernel
   allows for the same level of depth every time.

   In addition, some processes will spawn children that terminate
   abnormally after allocating some resources.

   We set EXPECTED_DEPTH_TO_PASS heuristically by
   giving *large* margin on the value from our implementation.
   If you seriously think there is no memory leak in your code
   but it fails with EXPECTED_DEPTH_TO_PASS,
   please manipulate it and report us the actual output.
   
   Orignally written by Godmar Back <godmar@gmail.com>
   Modified by Minkyu Jung, Jinyoung Oh <cs330_ta@casys.kaist.ac.kr>
*/

#include <debug.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <syscall.h>
#include <random.h>
#include "tests/lib.h"

static const int EXPECTED_DEPTH_TO_PASS = 10;
static const int EXPECTED_REPETITIONS = 10;

const char *test_name = "multi-oom";

int make_children (void);

/* Open a number of files (and fail to close them).
   The kernel must free any kernel resources associated
   with these file descriptors. */
static void
consume_some_resources (void)
{
  int fd, fdmax = 126; // fdmax만큼 루프를 돌면서 파일 디스크립터에 파일 열어줌.

  /* Open as many files as we can, up to fdmax.
	 Depending on how file descriptors are allocated inside
	 the kernel, open() may fail if the kernel is low on memory.
	 A low-memory condition in open() should not lead to the
	 termination of the process.  */
  for (fd = 0; fd < fdmax; fd++) { 
#ifdef EXTRA2
	  if (fd != 0 && (random_ulong () & 1)) {
		if (dup2(random_ulong () % fd, fd+fdmax) == -1)
			break;
		else
			if (open (test_name) == -1)
			  break;
	  }
#else
		if (open (test_name) == -1) // 루프 중간에 open 실패하면 중단.
		  break;
#endif
  }
}

/* Consume some resources, then terminate this process
   in some abnormal way.  */
static int NO_INLINE
consume_some_resources_and_die (void)
{
  consume_some_resources (); // 현재 프로세스의 파일 디스크립터 테이블을 채워넣음.
  int *KERN_BASE = (int *)0x8004000000; // kern base 정의

  switch (random_ulong () % 5) { // 초기화된 Pseudo Random Number Generator를 가지고 랜덤 넘버를 생성, 5가지 케이스를 무작위로 선택.
	case 0:
	  *(int *) NULL = 42; // 뭐야 이게. NULL 역참조 주소를 42로 바꿔버림. 커널 주소를 벗어나기 때문에 페이지 폴트가 발생 하려나?
    break;

	case 1:
	  return *(int *) NULL; // 

	case 2:
	  return *KERN_BASE;

	case 3:
	  *KERN_BASE = 42; // 커널 베이스의 값을 이상하게 바꿔버림.
    break;

	case 4:
	  open ((char *)KERN_BASE); 
	  exit (-1);
    break;

	default:
	  NOT_REACHED ();
  }
  return 0;
}

int
make_children (void) {
  int i = 0; // i 초기화
  int pid; // pid 선언. 자식의 pid인가?
  char child_name[128]; // 자식의 이름 담음.
  for (; ; random_init (i), i++) { // 종료 조건이 없음. random_init()는 시드(i)를 가지고 Psudo Random Number Generator를 초기화함. 난수의 목적은 비정상 종료 아무렇게나 던지기 위해서.
    if (i > EXPECTED_DEPTH_TO_PASS/2) { // 만약 i가 EXPECTED_DEPTH_TO_PASS(5) 이상이면 
      snprintf (child_name, sizeof child_name, "%s_%d_%s", "child", i, "X"); // 자식 이름을 설정. child_i_X. X의 의미는 뭐지?
      pid = fork(child_name); // 자식을 포크 뜨고 부모는 0보다 큰 수를 리턴.
      if (pid > 0 && wait (pid) != -1) { // 만약 포크 후 부모 프로세스가 자식을 기다렸는데 정상 종료가 됐다면 (exit코드로 -1을 리턴하지 않았다면)
        fail ("crashed child should return -1."); // 실패!
      } else if (pid == 0) { // 만약 포크 후 자식 프로세스일 경우
        consume_some_resources_and_die(); // 해당 함수 루틴으로 빠지고, 프로세스가 종료돼야 함. 
        fail ("Unreachable"); // 위에서 종료되지 않으면 역시 실패.
      }
    }
    // 이쪽 분기는 포크 후 부모프로세스가 자식을 기다린 결과 exit(-1)이 된 경우(적절한 예외 처리가 된 경우, 혹은 5번 이하 반복한 경우.)
    snprintf (child_name, sizeof child_name, "%s_%d_%s", "child", i, "O");  // 자식 이름을 설정. child_i_O. O의 의미는 또 뭐야?
    pid = fork(child_name); // 한번 더 포크를 수행.
    if (pid < 0) { // pid가 0보다 작다면? -1이라는 의미. 즉 포크에 실패.
      exit (i); // 그대로 종료.
    } else if (pid == 0) { // pid가 0이라면? 현재 프로세스는 자식.
      consume_some_resources();
    } else { // 현재세스 프로가 부모이고 pid > 0, 즉 정상 자식을 만들어 냈다면 
      break; // 부모 프로세스 루프 탈출.
    }
  }

  int depth = wait (pid); // 두 번째로 생성한 자식 pid로 기다리고 depth를 돌려받음. 이때 pid를 depth로 넣는다는 것은? 자식 프로세스의 종료 코드가 depth라는 의미일 것이다.
  if (depth < 0) // 깊이가 0보다 작다면: 자식이 비정상 종료.
	  fail ("Should return > 0."); // 실패.

  if (i == 0) // i 가 0이라는 뜻은 무슨 의미지? 
	  return depth; // 그대로 종료
  else
	  exit (depth); // depth를 상태 코드로 현재 프로세스 종료.
}

int
main (int argc UNUSED, char *argv[] UNUSED) { // 이건 뭐죠? 테스트 메인 함수지.
  msg ("begin"); // 시작 메시지야.

  int first_run_depth = make_children (); // 처음으로 make children 루틴을 수행하고 depth를 리턴. 리턴 없이 exit이 수행될 수도 있음. 
  // 리턴 된 depth가 EXPECTED_DEPTH_TO_PASS(10) 이상이어야 통과.
  CHECK (first_run_depth >= EXPECTED_DEPTH_TO_PASS, "Spawned at least %d children.", EXPECTED_DEPTH_TO_PASS); 

  // 10번 반복.
  for (int i = 0; i < EXPECTED_REPETITIONS; i++) {
    int current_run_depth = make_children();  // make children 루틴을 매번 반복.
    if (current_run_depth < first_run_depth) { // current_run_depth가 first_run_depth보다 작다면, 즉 메모리가 부족해져서 콜스택을 덜 생성하고 끝났으면 실패.
      fail ("should have forked at least %d times, but %d times forked", 
              first_run_depth, current_run_depth);
    }
  }
  // 성공 메시지.
  msg ("success. Program forked %d iterations.", EXPECTED_REPETITIONS);
  msg ("end");
}
