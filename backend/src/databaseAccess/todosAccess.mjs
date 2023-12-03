import { DynamoDB } from '@aws-sdk/client-dynamodb'
import { DynamoDBDocument } from '@aws-sdk/lib-dynamodb'
import AWSXRay from 'aws-xray-sdk-core'
import { createLogger } from '../utils/logger.mjs'

const logger = createLogger('databaseAccess/todosAccess.mjs')

export class TodoAccess {
    constructor(
        documentClient = AWSXRay.captureAWSv3Client(new DynamoDB()),
        todosTable = process.env.ITEM_TABLE
    ) {
        this.documentClient = documentClient
        this.todosTable = todosTable
        this.dynamoDbClient = DynamoDBDocument.from(this.documentClient)
    }

    async getAllTodos(userId) {
        logger.info(`Getting all todos of user_id ${userId}`, { function: "getAllTodos()" })

        const result = await this.dynamoDbClient.query({
            TableName: this.todosTable,
            KeyConditionExpression: 'userId = :userId',
            ExpressionAttributeValues: {
                ':userId': userId
            },
            ScanIndexForward: false
        })

        logger.info(`todos result = ${result}`, { function: "getAllTodos()" })

        return result.Items
    }

    async createTodo(todo) {
        logger.info(`Storing a new todo: ${todo}`, { function: "createTodo()" })

        await this.dynamoDbClient.put({
            TableName: this.todosTable,
            Item: todo
        })

        return todo
    }

    async updateTodo(updatedTodoItem) {
        logger.info(`Updating a updatedTodoItem: ${updatedTodoItem}`, { function: "updateTodo()" })

        const newUpdatedTodoItem = await this.dynamoDbClient
            .update({
                TableName: this.todosTable,
                Key: {
                    'userId': updatedTodoItem.userId,
                    'todoId': updatedTodoItem.todoId
                },

                UpdateExpression: 'set #task_name = :name, \
                              dueDate = :dueDate, \
                              done = :done',

                ConditionExpression: "(#task_name <> :name) or \
                              (dueDate <> :dueDate) or \
                              (done <> :done)",

                ExpressionAttributeValues: {
                    ':name': updatedTodoItem.name,
                    ':dueDate': updatedTodoItem.dueDate,
                    ':done': updatedTodoItem.done
                },

                ExpressionAttributeNames: {
                    '#task_name': 'name'
                },

                ReturnValues: 'UPDATED_NEW'
            })

        return newUpdatedTodoItem
    }

    async deleteTodo(deletedTodo) {
        logger.info(`Deleting a todo request: ${deletedTodo}`, { function: "deleteTodo()" })

        const deletedItem = await this.dynamoDbClient.delete({
            TableName: this.todosTable,
            Key: {
                'userId': deletedTodo.userId,
                'todoId': deletedTodo.todoId
            },
            ReturnValues: 'ALL_OLD'
        })

        logger.info(`deletedItem: ${deletedItem}`, { function: "deleteTodo()" })
        return deletedItem
    }

    async updateTodoAttachmentUrl(updatedTodoAttachment) {

        logger.info(`Updating a updatedTodoAttachment ${updatedTodoAttachment} `, { function: "updateTodoAttachmentUrl()" })

        const newUpdatedTodoAttachmentUrl = await this.dynamoDbClient.update({
            TableName: this.todosTable,
            Key: {
                'userId': updatedTodoAttachment.userId,
                'todoId': updatedTodoAttachment.todoId
            },

            UpdateExpression: 'set attachmentUrl = :attachmentUrl',

            ExpressionAttributeValues: {
                ':attachmentUrl': updatedTodoAttachment.attachmentUrl
            },

            ReturnValues: 'UPDATED_NEW'
        })

        return newUpdatedTodoAttachmentUrl
    }
}