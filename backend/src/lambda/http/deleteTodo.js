import middy from '@middy/core'
import cors from '@middy/http-cors'
import httpErrorHandler from '@middy/http-error-handler'
import { deleteTodo } from '../../businessLogic/todos.mjs'
import { createLogger } from '../../utils/logger.mjs'
import { getUserId } from '../utils.mjs'

const logger = createLogger('http/deleteTodos.js')

export const handler = middy()
  .use(httpErrorHandler())
  .use(
    cors({
      credentials: true
    })
  )
  .handler(async event => {
    const todoId = event.pathParameters.todoId

    // TODO: Remove a TODO item by id
    /* Get userId */
    const userId = getUserId(event)
    const deletedItem = await deleteTodo(todoId, userId)
    logger.info(`deletedItem = ${deletedItem}`, { function: "handler()" })

    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
      }
    }
  })