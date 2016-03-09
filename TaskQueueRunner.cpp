#include "TaskQueueRunner.h"

using namespace boost;

TaskQueueRunner::TaskQueueRunner()
	: running(100), pending(100)
{
}

void TaskQueueRunner::Enqueue(void* task)
{
	pending.push(task);
}

void TaskQueueRunner::Run()
{
	for (int i = 0; i < 10; i++)
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

	while (!pending.empty() || !running.empty())
	{
		void* first = nullptr;
		auto loop   = true;

		while (!running.empty() && loop)
		{
			void* task;

			if (!running.pop(task))
			{
				break;
			}

			if (task == first)
			{
				loop = false;
			}

			auto result = reinterpret_cast<void*(*)(void)>(task)();

			if (result == nullptr)
			{
				void* next;

				if (pending.pop(next))
				{
					running.push(next);

					if (first == task || first == nullptr)
					{
						first = next;
					}
				}
				else
				{
					first = nullptr;
				}
			}
			else
			{
				running.push(result);

				if (first == task || first == nullptr)
				{
					first = result;
				}
			}
		}
	}
}

TaskQueueRunner::~TaskQueueRunner()
{
}
