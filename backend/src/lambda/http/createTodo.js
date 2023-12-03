import middy from '@middy/core'
import cors from '@middy/http-cors'
import httpErrorHandler from '@middy/http-error-handler'
import { createTodo } from '../../businessLogic/todos.mjs'
import { createLogger } from '../../utils/logger.mjs'
import { getUserId } from '../utils.mjs'

const logger = createLogger('http/createTodos.js')

export const handler = middy()
  .use(httpErrorHandler())
  .use(
    cors({
      credentials: true
    })
  )
  .handler(async (event) => {
    const newTodo = JSON.parse(event.body)
    logger.info(`Processing newTodo ${newTodo}`, { function: "handler()" })

    // TODO: Implement creating a new TODO item
    /* Get userId */
    const userId = getUserId(event)
    const newItem = await createTodo(newTodo, userId)
    logger.info(`newItem = ${newItem}`, { function: "handler()" })

    return {
      statusCode: 201,
      headers: {
        'Access-Control-Allow-Origin': '*',
      },
      body: JSON.stringify({
        item: newItem
      })
    }
  })