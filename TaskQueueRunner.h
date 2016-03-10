#pragma once
#include <functional>
#include <boost/lockfree/queue.hpp>
#include "Service.h"
#include "ServiceScanner.h"

/*!
 * A macro that defines a pointer to a member function with arguments bound.
 * 
 * The function can be called by re-casting to std::function via `PTR_TO_MFN`.
 * 
 * Since the function instance is allocated on the heap, you are responsible
 * for deleting the pointer (re-casted with `PTR_TO_MFN`!) after use in order
 * to avoid memory leaks.
 *
 * \param fn The member function to call.
 * \param inst The instance on which to invoke the call.
 * \param ... Variable arguments bound to the function.
 * 
 * \return `void*` pointing to callable member function.
 */
#define MFN_TO_PTR(fn, inst, ...) reinterpret_cast<void*>(new std::function<void*(void)>(std::bind(&fn, inst, __VA_ARGS__)))

/*!
 * A macro that defines pointer to the underlying std::function of the `MFN_TO_PTR` call.
 * 
 * This pointer should be deleted after use, since the deletion of `void*` pointers
 * is undefined behaviour and most compilers will complain about it.
 * 
 * \param ptr The pointer created with `MFN_TO_PTR`.
 * 
 * \return `std::function` pointer.
 */
#define PTR_TO_MFN(ptr) reinterpret_cast<std::function<void*(void)>*>(ptr)

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
	 * Helper function to easily scan a list of services with a specified scanner.
	 *
	 * \param scanner The scanner instance to invoke on the services.
	 * \param services The list of services to scan.
	 */
	static void QuickScan(ServiceScanner& scanner, Services& services);

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
