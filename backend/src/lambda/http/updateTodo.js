import middy from '@middy/core'
import cors from '@middy/http-cors'
import httpErrorHandler from '@middy/http-error-handler'
import { updateTodo } from '../../businessLogic/todos.mjs'
import { createLogger } from '../../utils/logger.mjs'
import { getUserId } from '../utils.mjs'

const logger = createLogger('http/updateTodos.js')

export const handler = middy()
  .use(httpErrorHandler())
  .use(
    cors({
      credentials: true
    })
  )
  .handler(async event => {
    const todoId = event.pathParameters.todoId
    const updatedTodo = JSON.parse(event.body)

    // TODO: Update a TODO item with the provided id using values in the "updatedTodo" object
    /* Get userId */
    const userId = getUserId(event)
    const updatedItem = await updateTodo(todoId, updatedTodo, userId)
    logger.info(`updateItem = ${updatedItem}`, { function: "handler()" })

    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
      }
    }
  })