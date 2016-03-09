#pragma once
#include <boost/lockfree/queue.hpp>

/*!
 * Implements a task runner which uses two queues in order to differentiate between
 * running and pending tasks. Since network scan tasks mostly consist of waiting
 * for I/O operation results, it makes much more sense to multiplex the tasks in
 * this way.
 * 
 * A task gets into the `pending` queue. From there, the task runner will pick N
 * tasks and place them to the `running` queue. The `running` queue is looped,
 * the tasks are executed until a task is finished. When a task has finished,
 * it gets removed from the `running` queue and a new task will take its place
 * from the `pending` queue. The task runner stops when both queues are empty,
 * as it was inteded to receive all tasks before execution, as such it will not
 * block to wait for new tasks.
 */
class TaskQueueRunner
{
public:

	/*!
	 * Initializes a new instance of this class.
	 *
	 * \param capacity The total number of tasks to allocate space for.
	 * \param batch The number of tasks to execute in one batch.
	 */
	TaskQueueRunner(int capacity, int batch);

	/*!
	 * Enqueues a task for execution.
	 *
	 * \param task The task to be enqueued.
	 */
	void Enqueue(void* task);

	/*!
	 * Executes the tasks in the queue.
	 * 
	 * This call is blocking and will return when the task queue is exhausted.
	 */
	void Run();

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~TaskQueueRunner();

private:

	/*!
	 * The number of tasks to execute in one batch.
	 */
	int batch;

	/*!
	 * The queue of tasks currently being executed and are waiting for the result
	 * of an I/O operation.
	 */
	boost::lockfree::queue<void*> running;

	/*!
	 * The queue of tasks which are pending execution.
	 */
	boost::lockfree::queue<void*> pending;

};
