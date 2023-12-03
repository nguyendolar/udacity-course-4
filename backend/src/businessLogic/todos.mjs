import * as uuid from 'uuid'

import { TodoAccess } from '../databaseAccess/todosAccess.mjs'
import { getUploadUrl, getAttachmentUrl } from '../fileStorage/attachmentUtils.mjs'
import { createLogger } from '../utils/logger.mjs'

const logger = createLogger('businessLogic/todos.mjs')

const todoAccess = new TodoAccess()

export async function getAllTodos(userId) {
    logger.info(`Get all todos of User_Id ${userId}`, { function: 'getAllTodos()' })
    return todoAccess.getAllTodos(userId)
}

export async function createTodo(createTodoRequest, userId) {
    logger.info(`Create a new todo of User_ID ${userId}`, { function: 'createTodo()' })

    /* todoId */
    const todoId = uuid.v4()

    /* createdAt */
    const createdAt = new Date().toISOString()

    return await todoAccess.createTodo({
        todoId: todoId,
        userId: userId,
        attachmentUrl: "",
        dueDate: createTodoRequest.dueDate,
        createdAt: createdAt,
        name: createTodoRequest.name,
        done: false
    })
}

export async function updateTodo(todoId, updateTodoRequest, userId) {
    logger.info(`Update a todoId ${todoId} of userId ${userId}`, { function: 'updateTodo()' })

    return await todoAccess.updateTodo({
        todoId,
        userId,
        ...updateTodoRequest
    })
}


export async function deleteTodo(todoId, userId) {
    logger.info(`Delete a todoId ${todoId} of userId ${userId}`, { function: "deleteTodo()" })

    return await todoAccess.deleteTodo({
        todoId,
        userId
    })
}

export async function getTodoFileUploadUrl(todoId, userId) {
    logger.info(`Get uploadUrl for todoId ${todoId} of userId ${userId}`, { function: "getTodoFileUploadUrl()" })

    const fileId = uuid.v4()
    const uploadUrl = await getUploadUrl(fileId)

    /** Need to refactor later 
     * because having uploadUrl is not enough to gurantee have attachmentUrl
    */
    if (uploadUrl) {
        /* Updating attachmentUrl for todoId */
        const attachmentUrl = await todoAccess.updateTodoAttachmentUrl({
            userId,
            todoId,
            attachmentUrl: getAttachmentUrl(fileId)
        })

        logger.info(`attachmentUrl = ${attachmentUrl}`, { function: "getTodoFileUploadUrl()" })
    }

    return uploadUrl
}