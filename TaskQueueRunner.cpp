#include "TaskQueueRunner.h"

using namespace std;
using namespace boost;

TaskQueueRunner::TaskQueueRunner(int capacity, int batch)
	: batch(batch), running(batch), pending(capacity)
{
}

void TaskQueueRunner::Enqueue(void* task)
{
	pending.push(task);
}

void TaskQueueRunner::Run()
{
	// add the requested number of tasks from `pending` to `running`

	for (auto i = 0; i < batch; i++)
	{
		void* task;

		if (pending.pop(task))
		{
			running.push(task);
		}
		else
		{
			break;
		}
	}

	// loop until both queues are empty

	while (!pending.empty() || !running.empty())
	{
		void* task;

		if (!running.pop(task))
		{
			break;
		}

		// cast the task back to its original type and evaluate it

		auto func = PTR_TO_MFN(task);
		auto eval = (*func)();

		// since these pointers were created with `new std::function()`
		// we are the ones responsible to delete it after use

		delete func;

		// if the function evaluation returned a new function pointer,
		// put that one back into the queue. otherwise pop a new one
		// from the `pending` queue.

		if (eval != nullptr)
		{
			running.push(eval);
		}
		else
		{
			void* next;

			if (pending.pop(next))
			{
				running.push(next);
			}
		}
	}
}

void TaskQueueRunner::QuickScan(ServiceScanner& scanner, Services& services)
{
	TaskQueueRunner tqr(services.size(), 65535);

	for (auto service : services)
	{
		tqr.Enqueue(scanner.GetTask(service));
	}

	tqr.Run();
}

TaskQueueRunner::~TaskQueueRunner()
{
}
